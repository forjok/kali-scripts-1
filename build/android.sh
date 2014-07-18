#!/bin/bash

# Kernel Development requires Kali 64bit host

# Possibly use adb to send to device
# apt-get install -y android-sdk
# zip needed later for making flashable zip image
apt-get install -y zip

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/android-$1

# Make sure that the cross compiler can be found in the path before we do
# anything else, that way the builds don't fail half way through.
export CROSS_COMPILE=arm-linux-gnueabihf-
if [ $(compgen -c $CROSS_COMPILE | wc -l) -eq 0 ] ; then
    echo "Missing cross compiler. Set up PATH according to the README"
    exit 1
fi
# Unset CROSS_COMPILE so that if there is any native compiling needed it doesn't
# get cross compiled.
unset CROSS_COMPILE

# Package installations for various sections.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-menu kali-defaults initramfs-tools usbutils openjdk-7-jre"
desktop="kali-defaults kali-root-login desktop-base xfce4 xfce4-places-plugin xfce4-goodies"
tools="nmap metasploit tcpdump tshark wireshark burpsuite armitage sqlmap recon-ng wipe socat ettercap-text-only"
wireless="wifite iw aircrack-ng gpsd kismet kismet-plugins giskismet hostapd dnsmasq wvdial"
services="openssh-server lighttpd tightvncserver postgresql"
extras="wpasupplicant zip"

export packages="${arm} ${base} ${desktop} ${tools} ${wireless} ${services} ${extras}"
export architecture="armhf"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture kali kali-$architecture http://http.kali.org/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

# SECOND STAGE CHROOT

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage

cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
EOF

#define hostname

echo "kali" > kali-$architecture/etc/hostname

# fix for TUN symbolic link to enable programs like openvpn
cat << EOF > kali-$architecture/root/.bash_profile
if [ ! -d "/dev/net/" ]; then
  mkdir -p /dev/net
  ln -s /dev/tun /dev/net/tun
fi
EOF

cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       kali    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

cat << EOF > kali-$architecture/etc/network/interfaces
auto lo
iface lo inet loopback

auto wlan0
iface wlan0 inet dhcp
EOF

cat << EOF > kali-$architecture/etc/resolv.conf
#opendns
nameserver 208.67.222.222
nameserver 208.67.220.220
#googldns
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

# Fix for Armitage so it can run on Android.  Easier to create seperate binary as
# updates will destroy /usr/bin/armitage
cat << EOF > kali-$architecture/usr/bin/armitagearm
#!/bin/bash
cd /usr/share/armitage/ && export PATH=/usr/lib/jvm/java-7-openjdk-armhf/bin:$$PATH && ./armitage "$@"
EOF

# THIRD STAGE CHROOT

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools uboot-mkimage
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
apt-get --yes --force-yes install $packages

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C chroot kali-$architecture /third-stage

# Modify kismet configuration to work with gpsd and socat
sed -i 's/\# logprefix=\/some\/path\/to\/logs/logprefix=\/captures\/kismet/g' kali-$architecture/etc/kismet/kismet.conf
sed -i 's/gpshost=localhost:2947/gpshots=127.0.0.1:2947/g' kali-$architecture/etc/kismet/kismet.conf

# Modify Wifite log saving folder
sed -i 's/hs/\/captures/g' kali-$architecture/etc/kismet/kismet.conf


# DNSMASQ Configuration options for optional access point
# Default access point would be wlan0 however external USB
# Might be utilitized so this will be changed through a bash script

sed -i 's#^DAEMON_CONF=.*#DAEMON_CONF=/etc/hostapd/hostapd.conf#' kali-$architecture/etc/init.d/hostapd

cat <<EOF > kali-$architecture/etc/dnsmasq.conf
log-facility=/var/log/dnsmasq.log
#address=/#/10.0.0.1
#address=/google.com/10.0.0.1
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
#no-resolv
log-queries
EOF

cat <<EOF > kali-$architecture/etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=FreeWifi
channel=1
# Yes, we support the Karma attack.
#enable_karma=1
EOF

# Add missing folders to chroot needed
cap=kali-$architecture/captures

mkdir -p kali-$architecture/sdcard kali-$architecture/system
mkdir -p $cap/evilap $cap/ettercap $cap/kismet/db $cap/nmap $cap/sslstrip $cap/tshark $cap/wifite

# TEST CHROOT FOR DEBGGING
 LANG=C chroot kali-$architecture

# CLEANUP STAGE

#cat << EOF > kali-$architecture/cleanup
#!/bin/bash
#rm -rf /root/.bash_history
#apt-get update
#apt-get clean
#rm -f /0
#rm -f /hs_err*
#rm -f cleanup
#rm -f /usr/bin/qemu*
#EOF

#chmod +x kali-$architecture/cleanup
#LANG=C chroot kali-$architecture /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc



#####################################################
#  Create flashable Android FS
#  flashable zip will need follow structure:
#
#  /busybox/busybox - for mounting data folders
#  /data/app/terminal.apk - download terminal to ensure access to chroot
#  /data/local/kalifs.tar.bz2 - The filesystem
#  /data/local/tmp_kali - shell scripts to unzip filesystem/boot chroot
#  /kernel/zImage - kernel
#  /META-INF/com/google/android/updater-binary - Binary file for edify script
#  /META-INF/com/google/android/updater-script - Edify script to install Kali 
#####################################################

# Create base flashable zip using Koush's AnyKernel
git clone https://github.com/koush/AnyKernel.git ${basedir}/flash
rm -rf ${basedir}/flash/system/lib 

# Create necessary folders for flashing
mkdir -p ${basedir}/flash/data/local/ ${basedir}/flash/data/tmp_kali ${basedir}/flash/busybox ${basedir}/flash/kernel ${basedir}/flash/system/etc/firmware 

# Maybe compile busybox with Android toolchain instead and download terminal application....
wget -P http://benno.id.au/android/busybox ${basedir}/flash/busybox
wget -P ${basedir}/flash/data/app/ http://jackpal.github.com/Android-Terminal-Emulator/downloads/Term.apk


# tmp kali script used to extract rootfs to /data/local/
cat << EOF > ${basedir}/flash/data/tmp_kali/extractkali.sh 
!/sbin/sh
if [ -d "/data/local/kali"]; then
	rm /data/local/kalifs.tar.bz2
	echo "Kali folder detected...skipping extraction"
else
	tar -jxvf /data/local/kalifs.tar.bz2 -C /data/local
	rm /data/local/kalifs.tar.bz2
fi
EOF

# bootkali script for /data/local/ which will launch the Kali chroot


# Create updater-script that will be the installer

cat << EOF > ${basedir}/flash/META-INF/com/google/android/updater-script
ui_print("************************************************");
ui_print("****__****__*******___*********__********__*****");
ui_print("***|\__\*/\__\****/\___\******|\__\*****|\__\***");
ui_print("***||  |/ /  /***/ /    \*****||  |*****||  |***");
ui_print("***||  | /  /***/ /  /,  \****||  |*****||  |***");
ui_print("***||  |/  /***/ /  /__\  \***||  |*****||  |***");
ui_print("***||  |\  \**/ /  ______  \**||  |___ *||  |***");
ui_print("***||  |*\  \/ /  /******\  \*||  |____\||  |***");
ui_print("***\|__|**\__\/__/********\_ \||_______|\|__|***");
ui_print("************************************************");
ui_print("************************************************");
ui_print("AnyKernel Updater by Koush.");
ui_print("Extracting System Files...");
show_progress(1.34, 700);
package_extract_dir("busybox", "/tmp");
set_perm(0, 0, 0755, "/tmp/busybox");
ui_print("*Installing Kali chroot...                     *");
ui_print("*Be aware, this will take ~30 minutes..        *");
ui_print("*Mounting system and rootfs...                 *");
run_program("/tmp/busybox", "mount", "/system");
run_program("/tmp/busybox", "mount", "-o", "rw,remount", "/system", "/system");
run_program("/tmp/busybox", "mount", "/data");
run_program("/tmp/busybox", "mount", "-o", "rw,remount", "/", "/");
ui_print("*Removing any old terminal/ssh applications... *");
delete("/system/app/Term.apk", "/system/app/com.android.term1.apk", "/system/app/com.android.term2.apk", 
"/system/app/com.android.term3.apk", "/system/app/com.android.term4.apk", "/system/app/com.android.term5.apk", "/system/app/jackpal.androidterm.apk", 
"/system/app/jackpal.androidterm-1.apk", "/system/app/jackpal.androidterm-2.apk", "/system/app/AndroidTerm.apk", 
"/system/app/AndroidTerm-1.apk", "/system/app/AndroidTerm-2.apk", "/data/app/Term.apk", "/data/app/jackpal.androidterm.apk", 
"/data/app/jackpal.androidterm-1.apk", "/data/app/jackpal.androidterm-2.apk", "/data/app/AndroidTerm.apk", "/data/app/AndroidTerm-1.apk", "/data/app/AndroidTerm-2.apk");
ui_print("*Extracting system files and applications...   *");
package_extract_dir("system", "/system");
set_perm_recursive(0, 2000, 0755, 0755, "/system/bin");
set_perm_recursive(0, 2000, 0755, 0755, "/system/xbin");
ui_print("*Copying compressed Kali 1GB filesystem...     *");
ui_print("*Along with temporary files...                 *");
package_extract_dir("data/local", "/data/local");
package_extract_dir("data/app", "/data/app");
package_extract_dir("data/tmp_kali", "/tmp");
package_extract_file("data/tmp_kali/bootkali", "/data/local/bootkali");
ui_print("*Setting permissions...                        *");
set_perm(0, 0, 0755, "/data/local/bootkali");
set_perm(0, 0, 0777, "/data/local/kalifs.tar.bz2");
set_perm(0, 0, 0755, "/tmp/extractkali.sh");
ui_print("*Extracting Kali chroot...                     *");
ui_print("*This takes around 30 minutes...               *");
run_program("/tmp/extractkali.sh");
ui_print("*Kali chroot is now successfully installed.    *");
ui_print("*Extracting Kernel files...");
package_extract_dir("kernel", "/tmp");
ui_print("Installing kernel...");
set_perm(0, 0, 0777, "/tmp/dump_image");
set_perm(0, 0, 0777, "/tmp/mkbootimg.sh");
set_perm(0, 0, 0777, "/tmp/mkbootimg");
set_perm(0, 0, 0777, "/tmp/unpackbootimg");
run_program("/tmp/dump_image", "boot", "/tmp/boot.img");
run_program("/tmp/unpackbootimg", "/tmp/boot.img", "/tmp/");
run_program("/tmp/mkbootimg.sh");
write_raw_image("/tmp/newboot.img", "boot");
delete_recursive("/tmp");
ui_print("*Unmounting system..                           *");
unmount("/system");
ui_print("*Unmounting data...                            *");
unmount("/data");
EOF

# Compress filesystem and add to our flashable zip
tar jcvf ${basedir}/flash/data/local/kali/kalifs.tar.bz2 ${basedir}kali-$architecture

#####################################################
# Create Nexus 10 Kernel (4.4+)
#####################################################
# Set paths
export ARCH=arm
export SUBARCH=arm
export CROSS_COMPILE=${basedir}/toolchain/bin/arm-eabi-
# Get android toolchain to compile kernel
git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8 toolchain
# Using Thunderkat kernel but feel free to change
git clone https://github.com/craigacgomez/kernel_samsung_manta.git -b thunderkat ${basedir}/kernel
cd ${basedir}/kernel
# Applying wireless patches
mkdir -p ../patches
wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O ../patches/mac80211.patch
wget http://patches.aircrack-ng.org/channel-negative-one-maxim.patch -O ../patches/negative.patch
patch -p1 --no-backup-if-mismatch < ../patches/mac80211.patch
patch -p1 --no-backup-if-mismatch < ../patches/negative.patch
make clean
make thunderkat_manta_defconfig
wget https://raw.githubusercontent.com/binkybear/kali-scripts/master/defconfigs/nexus10-thunderkat/thunderkali_defconfig -O .config
make -j $(grep -c processor /proc/cpuinfo)
cp ${basedir}/kernel/arch/arm/boot/zImage ${basedir}/flash/kernel/zImage
cd ${basedir}

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
#echo "Removing temporary build files"
#rm -rf ${basedir}/patches ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/boot
