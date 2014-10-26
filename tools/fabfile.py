# This is a script used to build a shadow vm from scratch

from fabric.api import env, local, run
from fabric.api import run, cd, sudo, put, get, env, settings
from fabric.contrib.files import append
 
def vagrant():
    # change from the default user to 'vagrant'
    env.user = 'vagrant'
    # connect to the port-forwarded ssh
    env.hosts = ['127.0.0.1:2222']
 
    # use vagrant ssh key
    result = local('vagrant ssh-config | grep IdentityFile', capture=True)
    env.key_filename = result.split()[1] # strip ""
    print 'key: [%s]' % env.key_filename

def setup_apt():
    sudo('apt-get install -y build-essential git libdb++-dev python-software-properties')
    sudo('apt-get install -y libtool autotools-dev autoconf pkg-config gdb dc')
    sudo('add-apt-repository -y ppa:kalakris/cmake')
    #sudo('apt-get --fix-missing update; true')
    sudo('apt-get install -y libminiupnpc-dev cmake clang-3.4 clang-3.4++ llvm-3.4-dev')
    sudo('apt-get install -y libglib2.0-dev libigraph0-dev xz-utils liblz1 libevent-dev')
    sudo('apt-get install -y automake emacs23-nox libssl-dev pkg-config curl')
    sudo('update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-3.4 33')
    sudo('update-alternatives --install /usr/bin/llvm-bcanalyzer llvm-bcanalyzer /usr/bin/llvm-bcanalyzer-3.4 33')
    sudo('update-alternatives --install /usr/bin/llvm-ranlib llvm-ranlib /usr/bin/llvm-ranlib-3.4 33')
    sudo('update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-3.4 33')
    sudo('update-alternatives --install /usr/bin/opt llvm-opt /usr/bin/opt-3.4 33')
    sudo('update-alternatives --install /usr/include/llvm llvm-include /usr/include/llvm-3.4/llvm 33')
    sudo('update-alternatives --install /usr/include/llvm-c llvm-c-include /usr/include/llvm-c-3.4/llvm-c 33')



def setup():
    # Builds/installs bitcoin
    run('mkdir -p installing')
    with cd('installing'):
        run('if ! [ -a bitcoin ]; then git clone https://github.com/bitcoin/bitcoin; fi')
        with cd('bitcoin'):
            run('git pull origin master')
            run('if ! [ -a configure.sh ]; then ./autogen.sh; fi')
            run('./configure --with-incompatible-bdb --enable-tests=no')
            run('make')

    run('mkdir -p ~/.bitcoin')
    run('echo "rpcuser=nothing\nrpcpassword=0932jf0j9sdjf" > ~/.bitcoin/bitcoin.conf')
    run('mkdir -p ~/bin')
    run('if ! [ -a ~/bin/bitcoind ]; then ln -s $HOME/installing/bitcoin/src/bitcoind $HOME/bin/bitcoind; fi')

def setup_shadow():
    run('mkdir -p installing')
    with cd('installing'):
        run('if ! [ -a shadow ]; then git clone https://github.com/shadow/shadow; fi')
        with cd('shadow'):
            run('git pull origin master')
            run('./setup build -fg')
            run('./setup install')

def setup_extras():
    run('mkdir -p installing')
    with cd('installing'):
        run('if ! [ -a shadow-plugin-extras ]; then git clone https://github.com/amiller/shadow-plugin-extras; fi')
        with cd('shadow-plugin-extras'):
            run('git checkout local-sockets')
            run('git pull')
            run('mkdir -p build')
            with cd('build'):
                # Dependencies

                # Gnu-Pth
                run('if ! [ -a gnu-pth ]; then git clone https://github.com/amiller/gnu-pth.git -b shadow; fi')
                with cd('gnu-pth'):
                    run('git pull')
                    run('./configure --enable-epoll')

                run('CXX=clang++ CC=clang cmake ..')
                run('make')
                run('make install')

        

def setup_plugin_deps():
    run('mkdir -p installing')
    with cd('installing'):
        run('if ! [ -a shadow-plugin-bitcoin ]; then git clone https://github.com/amiller/shadow-plugin-bitcoin; fi')
        with cd('shadow-plugin-bitcoin'):
            run('git checkout with-pth')
            run('mkdir -p build')
            with cd('build'):
                # Dependencies

                # Libev
                run('if ! [ -a libev-4.15 ]; then wget http://pkgs.fedoraproject.org/lookaside/pkgs/libev/libev-4.15.tar.gz/3a73f247e790e2590c01f3492136ed31/libev-4.15.tar.gz; tar -zxf libev-4.15.tar.gz; fi')
                with cd('libev-4.15'):
                    run('./configure')

                # Netmine
                # TODO... this is a UMD private repository

                # Picocoin
                run('if ! [ -a picocoin ]; then git clone https://github.com/amiller/picocoin; fi')
                with cd('picocoin'):
                    run('git pull')
                    run('./autogen.sh')
                    run('./configure LDFLAGS="-L${HOME}/.shadow/lib -L${HOME}/.local/lib"')
                
                # Boost
                run('if ! [ -a boost_1_50_0 ]; then curl -L -O http://downloads.sourceforge.net/project/boost/boost/1.50.0/boost_1_50_0.tar.gz; tar -xzf boost_1_50_0.tar.gz; fi')
                with cd('boost_1_50_0'):
                    run('./bootstrap.sh --with-libraries=filesystem,system,thread,program_options')
                    run('./b2')

                # Bitcoin
                run('if ! [ -a bitcoin ]; then git clone https://github.com/amiller/bitcoin.git; fi')
                with cd('bitcoin'):
                    run('git checkout 0.9.2-netmine')
                    run('git pull')
                    run('./autogen.sh')
                    run('PKG_CONFIG_PATH=/home/${USER}/.shadow/lib/pkgconfig LDFLAGS=-L/home/${USER}/.shadow/lib CFLAGS=-I/home/${USER}/.shadow/include CXXFLAGS=-I`pwd`/../boost_1_50_0 ./configure --prefix=/home/${USER}/.shadow --without-miniupnpc --without-gui --disable-wallet --disable-tests --with-boost-libdir=`pwd`/../boost_1_50_0/stage/lib')

                # Gnu-Pth
                run('if ! [ -a gnu-pth ]; then git clone https://github.com/amiller/gnu-pth.git -b shadow; fi')
                with cd('gnu-pth'):
                    run('git pull')
                    run('./configure --enable-epoll')

                # Jansson
                run('if ! [ -a jansson-2.6 ]; then curl -L -O http://www.digip.org/jansson/releases/jansson-2.6.tar.gz; tar -xzf jansson-2.6.tar.gz; fi')
                with cd('jansson-2.6'):
                    run('./configure --prefix=${HOME}/.local')
                    run('make install')


def setup_plugin():
    run('mkdir -p installing')
    with cd('installing'):
        run('if ! [ -a shadow-plugin-bitcoin ]; then git clone https://github.com/amiller/shadow-plugin-bitcoin; fi')
        with cd('shadow-plugin-bitcoin'):
            run('git checkout with-pth')
            run('git pull')
            run('mkdir -p build')
            with cd('build'):
                run('CXX=clang++ CC=clang cmake ..')
                run('make')
                run('make install')

def run_plugin():
    with cd('installing/shadow-plugin-bitcoin/build'):
        #run('${HOME}/.shadow/bin/shadow --preload=${HOME}/.shadow/lib/libshadow-preload-bitcoind.so  ${HOME}/installing/shadow-plugin-bitcoin/resource/shadow.config.xml')
        run('LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH:$HOME/.shadow/lib')
        run('killall -9 shadow; ../src/bitcoind/shadow-bitcoind -y -i ../resource/shadow.config.xml -t -r 2 -T initdata/dotbitcoin_template_120k -w 2')

def start():
    run('bitcoind -daemon -debug')

def getinfo():
    run('bitcoind getinfo')

def uname():
    run('uname -a')
