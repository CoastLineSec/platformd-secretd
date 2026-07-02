# Maintainer: James <new.hall8904@fastmail.com>
#
# Builds platformd-secretd from this local checkout. Run `makepkg -si` from the
# repository root. (For a plain install, `sudo meson install -C build` also works
# once the tree is configured.)

pkgname=platformd-secretd
pkgver=0.0.1
pkgrel=1
pkgdesc='Platform-authentication-aware Secret Service provider (org.freedesktop.secrets)'
arch=('x86_64')
url='https://github.com/CoastLineSec/platformd-secretd'
license=('LGPL-2.1-or-later')
depends=('systemd-libs' 'openssl')
makedepends=('meson' 'ninja' 'pkgconf' 'systemd' 'libxslt' 'docbook-xsl')
# No source(): built from the working tree ($startdir).

build() {
	meson setup "$startdir" "$srcdir/build" \
		--prefix=/usr --buildtype=release --wipe
	meson compile -C "$srcdir/build"
}

check() {
	meson test -C "$srcdir/build"
}

package() {
	meson install -C "$srcdir/build" --destdir "$pkgdir"
}
