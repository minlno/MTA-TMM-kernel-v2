NCPU=40
make -j $NCPU
make modules -j $NCPU
sudo make INSTALL_MOD_STRIP=1 modules_install -j $NCPU
sudo make install -j $NCPU
