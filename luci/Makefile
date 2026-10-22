include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for warpq (Cloudflare WARP over MASQUE)
LUCI_DEPENDS:=+warpq
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-warpq
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

LUCI_MK:=$(wildcard $(TOPDIR)/feeds/luci/luci.mk)
include $(if $(LUCI_MK),$(LUCI_MK),../../luci.mk)
