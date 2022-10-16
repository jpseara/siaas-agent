WORKING_DIR=/data/rpi

#IMG_URI=https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-01-12/2021-01-11-raspios-buster-armhf-lite.zip
IMG_URI=https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2022-09-26/2022-09-22-raspios-bullseye-armhf-lite.img.xz

#sudo apt-get update && sudo apt-get install qemu-system-arm qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils virtinst libvirt-daemon virt-manager

ZIP_FILE=`basename $IMG_URI`
IMG_FILE=`basename $IMG_URI | cut -f1-2 -d"."`

cd $WORKING_DIR

wget $IMG_URI
xz -d $ZIP_FILE || unzip $ZIP_FILE

rm -rf qemu-rpi-kernel && git clone https://github.com/dhruvvyas90/qemu-rpi-kernel

sudo virt-install \
  --name RPI  \
  --arch armv6l \
  --machine versatilepb \
  --cpu arm1176 \
  --vcpus 1 \
  --memory 256 \
  --import  \
  --disk $IMG_FILE,format=raw,bus=virtio \
  --network bridge,source=virbr0,model=virtio  \
  --video vga  \
  --graphics spice \
  --boot 'dtb=qemu-rpi-kernel/versatile-pb-buster.dtb,kernel=qemu-rpi-kernel/kernel-qemu-4.19.50-buster,kernel_args=root=/dev/vda2 panic=1' \
  --events on_reboot=destroy \
  --osinfo detect=on,require=off

rm -f $ZIP_FILE
