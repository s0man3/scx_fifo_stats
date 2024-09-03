mkdir -p mnt
sudo mount bin/rootfs.ext2 mnt
sudo cp bin/scx/* mnt/root/
sudo umount mnt
rmdir mnt
