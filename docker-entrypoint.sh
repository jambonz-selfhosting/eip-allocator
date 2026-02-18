#!/bin/bash
set -e

# Multi-cloud EIP allocator for jambonz SBC nodes.
# Assigns a static/elastic IP to the instance this pod runs on.
#
# Required env vars:
#   CLOUD                - Cloud provider: aws, exoscale, gcp
#   EIP_GROUP_ROLE_KEY   - Tag/label key used to identify the EIP pool
#   EIP_GROUP_ROLE       - Tag/label value identifying this node's EIP pool
#
# Cloud-specific env vars:
#   AWS: uses instance metadata + IAM role (no extra env vars needed)
#   Exoscale: EXOSCALE_API_KEY, EXOSCALE_API_SECRET, EXOSCALE_ZONE
#   GCP: uses instance metadata + service account (needs compute-rw scope)

log() { echo "[eip-allocator] $*"; }
die() { echo "[eip-allocator] ERROR: $*" >&2; exit 1; }

: "${CLOUD:?CLOUD env var is required (aws, exoscale, gcp)}"
: "${EIP_GROUP_ROLE_KEY:?EIP_GROUP_ROLE_KEY env var is required}"
: "${EIP_GROUP_ROLE:?EIP_GROUP_ROLE env var is required}"

#
# AWS: uses EC2 metadata service + aws cli
#
allocate_aws() {
  log "Cloud: AWS"

  # Get IMDSv2 token
  TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

  INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/instance-id)
  PUBLIC_IP=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  REGION=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)

  log "Instance: $INSTANCE_ID, Region: $REGION, Current public IP: $PUBLIC_IP"

  NETWORK_INTERFACE_ID=$(aws ec2 describe-network-interfaces \
    --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
    --region "$REGION" \
    --query 'NetworkInterfaces[0].NetworkInterfaceId' --output text)

  # Get pool EIPs
  POOL_IPS=$(aws ec2 describe-addresses \
    --filters "Name=tag:${EIP_GROUP_ROLE_KEY},Values=${EIP_GROUP_ROLE}" \
    --region "$REGION" \
    --query 'Addresses[].PublicIp' --output text)

  # Check if current IP is already from the pool
  for EIP in $POOL_IPS; do
    if [[ "$PUBLIC_IP" == "$EIP" ]]; then
      log "Already have pool EIP $EIP assigned, nothing to do"
      return 0
    fi
  done

  # Find first unassociated EIP in the pool
  ALLOCATION_ID=$(aws ec2 describe-addresses \
    --filters "Name=tag:${EIP_GROUP_ROLE_KEY},Values=${EIP_GROUP_ROLE}" \
    --region "$REGION" \
    --query 'Addresses[?AssociationId==null].AllocationId | [0]' --output text)

  if [[ -z "$ALLOCATION_ID" || "$ALLOCATION_ID" == "None" ]]; then
    die "No free EIPs available in pool ${EIP_GROUP_ROLE}"
  fi

  log "Associating EIP allocation $ALLOCATION_ID to interface $NETWORK_INTERFACE_ID"
  aws ec2 associate-address \
    --allocation-id "$ALLOCATION_ID" \
    --network-interface-id "$NETWORK_INTERFACE_ID" \
    --region "$REGION" \
    --no-allow-reassociation

  log "EIP associated successfully"
}

#
# Exoscale: uses metadata service + exo CLI
#
allocate_exoscale() {
  log "Cloud: Exoscale"
  log "Zone: $EXOSCALE_ZONE, EIP pool: ${EIP_GROUP_ROLE_KEY}=${EIP_GROUP_ROLE}"

  : "${EXOSCALE_API_KEY:?EXOSCALE_API_KEY env var is required for Exoscale}"
  : "${EXOSCALE_API_SECRET:?EXOSCALE_API_SECRET env var is required for Exoscale}"
  : "${EXOSCALE_ZONE:?EXOSCALE_ZONE env var is required for Exoscale}"

  # Get instance ID from metadata service
  INSTANCE_ID=$(curl -sf http://169.254.169.254/1.0/meta-data/instance-id)
  if [[ -z "$INSTANCE_ID" ]]; then
    die "Failed to get instance ID from metadata service"
  fi
  log "Instance ID: $INSTANCE_ID"

  # Get current EIPs attached to this instance
  local current_eips
  current_eips=$(exo compute instance show "$INSTANCE_ID" -z "$EXOSCALE_ZONE" -O json \
    | jq -r '.elastic_ips[]?.id // empty' 2>/dev/null)
  if [[ -n "$current_eips" ]]; then
    log "Instance currently has EIPs: $current_eips"
  else
    log "Instance has no EIPs currently attached"
  fi

  # List all EIPs then query each one individually to get full details.
  # (elastic-ip list only returns id/ip_address/zone; description and instances
  # are only available via elastic-ip show)
  local all_eips_json
  all_eips_json=$(exo compute elastic-ip list -z "$EXOSCALE_ZONE" -O json)

  local all_eip_ids
  all_eip_ids=$(echo "$all_eips_json" | jq -r '.[].id')
  local total_eips
  total_eips=$(echo "$all_eip_ids" | wc -w | tr -d ' ')
  log "Found $total_eips total EIPs in zone $EXOSCALE_ZONE"

  # Query each EIP to find pool members by description match
  local match="${EIP_GROUP_ROLE_KEY}=${EIP_GROUP_ROLE}"
  log "Looking for EIPs with description '${match}'"

  local pool_eips="" pool_count=0
  local free_eip="" eip_ip=""
  for eip_id in $all_eip_ids; do
    local eip_json
    eip_json=$(exo compute elastic-ip show "$eip_id" -z "$EXOSCALE_ZONE" -O json)
    local desc
    desc=$(echo "$eip_json" | jq -r '.description // empty')
    local this_ip
    this_ip=$(echo "$eip_json" | jq -r '.ip_address')

    if [[ "$desc" != "$match" ]]; then
      log "EIP $eip_id ($this_ip) description='${desc:-<empty>}', not in pool"
      continue
    fi

    pool_count=$((pool_count + 1))
    pool_eips="$pool_eips $eip_id"

    # Check if this instance already has this pool EIP
    for current_id in $current_eips; do
      if [[ "$eip_id" == "$current_id" ]]; then
        log "Already have pool EIP $eip_id ($this_ip) assigned, nothing to do"
        return 0
      fi
    done

    # Check if this EIP is free (not attached to any instance)
    local attached
    attached=$(echo "$eip_json" | jq -r '.instances // empty')
    if [[ -z "$attached" || "$attached" == "null" ]]; then
      if [[ -z "$free_eip" ]]; then
        log "EIP $eip_id ($this_ip) is free"
        free_eip="$eip_id"
        eip_ip="$this_ip"
      fi
    else
      log "EIP $eip_id ($this_ip) is attached, skipping"
    fi
  done

  if [[ $pool_count -eq 0 ]]; then
    die "No EIPs found with description '${match}'"
  fi

  log "Found $pool_count EIPs in pool"

  if [[ -z "$free_eip" ]]; then
    die "No free EIPs available in pool (all $pool_count EIPs are attached)"
  fi

  log "Attaching EIP $free_eip ($eip_ip) to instance $INSTANCE_ID"

  exo compute instance elastic-ip attach "$INSTANCE_ID" "$free_eip" -z "$EXOSCALE_ZONE"

  log "EIP $eip_ip attached successfully to instance $INSTANCE_ID"
}

#
# GCP: uses metadata service + Compute REST API (no gcloud dependency)
#
allocate_gcp() {
  log "Cloud: GCP"

  local METADATA="http://metadata.google.internal/computeMetadata/v1"
  local HDR="Metadata-Flavor: Google"
  local COMPUTE="https://compute.googleapis.com/compute/v1"

  INSTANCE_NAME=$(curl -sf -H "$HDR" "${METADATA}/instance/name")
  ZONE_PATH=$(curl -sf -H "$HDR" "${METADATA}/instance/zone")
  ZONE=$(echo "$ZONE_PATH" | awk -F/ '{print $NF}')
  PROJECT=$(curl -sf -H "$HDR" "${METADATA}/project/project-id")
  REGION=$(echo "$ZONE" | sed 's/-[a-z]$//')

  # Get OAuth token from metadata service (uses node's service account)
  ACCESS_TOKEN=$(curl -sf -H "$HDR" \
    "${METADATA}/instance/service-accounts/default/token" | jq -r .access_token)

  log "Instance: $INSTANCE_NAME, Zone: $ZONE, Project: $PROJECT, Region: $REGION"

  gcp_api() {
    curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" "$@"
  }

  # Get instance details for current external IP
  local instance_json
  instance_json=$(gcp_api "${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/${INSTANCE_NAME}")

  local current_ip
  current_ip=$(echo "$instance_json" | jq -r \
    '.networkInterfaces[0].accessConfigs[0].natIP // empty')
  local access_config_name
  access_config_name=$(echo "$instance_json" | jq -r \
    '.networkInterfaces[0].accessConfigs[0].name // "External NAT"')
  local nic_name
  nic_name=$(echo "$instance_json" | jq -r '.networkInterfaces[0].name // "nic0"')

  log "Current external IP: $current_ip"

  # List all static addresses in the region
  local addresses_json
  addresses_json=$(gcp_api "${COMPUTE}/projects/${PROJECT}/regions/${REGION}/addresses")

  # Filter by label and check if current IP is already a pool IP
  local pool_reserved pool_all_ips
  pool_all_ips=$(echo "$addresses_json" | jq -r \
    --arg key "$EIP_GROUP_ROLE_KEY" \
    --arg val "$EIP_GROUP_ROLE" \
    '.items[]? | select(.labels[$key] == $val) | .address')

  for ip in $pool_all_ips; do
    if [[ "$current_ip" == "$ip" ]]; then
      log "Already have pool static IP $ip assigned, nothing to do"
      return 0
    fi
  done

  # Find first RESERVED (unassigned) address from the pool
  pool_reserved=$(echo "$addresses_json" | jq -r \
    --arg key "$EIP_GROUP_ROLE_KEY" \
    --arg val "$EIP_GROUP_ROLE" \
    '[.items[]? | select(.labels[$key] == $val and .status == "RESERVED")] | first')

  if [[ -z "$pool_reserved" || "$pool_reserved" == "null" ]]; then
    die "No free static IPs available in pool ${EIP_GROUP_ROLE_KEY}=${EIP_GROUP_ROLE}"
  fi

  local addr_ip
  addr_ip=$(echo "$pool_reserved" | jq -r '.address')

  log "Assigning static IP $addr_ip"

  # Delete current access config (ephemeral IP)
  gcp_api -X POST \
    "${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/${INSTANCE_NAME}/deleteAccessConfig?accessConfig=${access_config_name}&networkInterface=${nic_name}" \
    2>/dev/null || true

  # Add new access config with static IP
  gcp_api -X POST \
    -d "{\"natIP\": \"${addr_ip}\", \"name\": \"${access_config_name}\", \"type\": \"ONE_TO_ONE_NAT\"}" \
    "${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/${INSTANCE_NAME}/addAccessConfig?networkInterface=${nic_name}"

  log "Static IP assigned successfully"
}

# Dispatch to cloud-specific handler
case "$CLOUD" in
  aws)
    allocate_aws
    ;;
  exoscale)
    allocate_exoscale
    ;;
  gcp)
    allocate_gcp
    ;;
  *)
    log "EIP allocation not supported for cloud provider: $CLOUD (supported: aws, exoscale, gcp), skipping"
    ;;
esac