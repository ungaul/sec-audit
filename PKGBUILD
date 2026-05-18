# Maintainer: ungaul <arch@0x404.org>
pkgname=sec-audit
pkgver=0.1.0
pkgrel=1
pkgdesc="Linux privacy and security auditor"
arch=('x86_64' 'aarch64')
url="https://github.com/ungaul/sec-audit"
license=('MIT')

makedepends=(
    'cmake'
    'ninja'
    'gcc'
)

optdepends=(
    'bind-tools: DNS resolution for telemetry connection check'
    'usbutils: USB device enumeration'
    'usbguard: USB device authorization enforcement'
    'curl: external IP and geolocation lookup'
)

source=("$pkgname-$pkgver.tar.gz::https://github.com/ungaul/$pkgname/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    cmake -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build --parallel
}

package() {
    cd "$pkgname-$pkgver"
    DESTDIR="$pkgdir" cmake --install build
}
