#!/bin/bash
NS1="das"
NS2="cas"

# ========== first
IP1="[::]"
LUN1=14
LUN2=13
LUN3=12
LUN4=11

#DEV1="/dev/zvol/z_apool/zvol-dec-1"
NS1_DEV1="/dev/sdb"
#NS1_DEV2="/dev/nvme1n1"
#DEV3="/dev/sda"
#DEV4="/dev/sdb"
#DEV1="/dev/disk/by-id/nvme-ADATA_SX8200PNP_2L09291GATKT"
#DEV1="/dev/zvol/apool/nvmet/zfs_dec"
#DEV2="/dev/zvol/apool/nvmet/dec"

modprobe nvmet
modprobe nvmet-rdma

mkdir /sys/kernel/config/nvmet/ports/1
cd /sys/kernel/config/nvmet/ports/1
echo ipv6 > addr_adrfam
echo "::" > addr_traddr
echo rdma > addr_trtype
echo 4420 > addr_trsvcid

mkdir /sys/kernel/config/nvmet/ports/2
cd /sys/kernel/config/nvmet/ports/2
echo ipv4 > addr_adrfam
echo "0.0.0.0" > addr_traddr
echo rdma > addr_trtype
echo 4420 > addr_trsvcid

# iterate namespaces
for nsi in {1..5}; do
  NSP=NS$nsi
  [ "${!NSP}" ] || break;
  echo $nsi  ${!NSP}

  TGT=/sys/kernel/config/nvmet/subsystems/${!NSP}
  mkdir ${TGT}
  echo 1 > ${TGT}/attr_allow_any_host

  for devi in {1..9}; do
    DEV=NS${nsi}_DEV${devi}
    [ "${!DEV}" ] || break;
    LUN=1${devi}

    echo $devi ${!DEV} $LUN

    mkdir ${TGT}/namespaces/$LUN
    echo -n ${!DEV} > ${TGT}/namespaces/$LUN/device_path
    echo 1 > ${TGT}/namespaces/$LUN/enable
  done
  ln -s /sys/kernel/config/nvmet/subsystems/${!NSP} /sys/kernel/config/nvmet/ports/1/subsystems/${!NSP}
  ln -s /sys/kernel/config/nvmet/subsystems/${!NSP} /sys/kernel/config/nvmet/ports/2/subsystems/${!NSP}
done
