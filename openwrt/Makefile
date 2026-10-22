include $(TOPDIR)/rules.mk

PKG_NAME:=warpq
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=warpq

include $(INCLUDE_DIR)/package.mk

define Package/warpq
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Minimal Cloudflare WARP MASQUE client
  URL:=https://github.com/WorldEditAxe/warpq-c
  DEPENDS:=+libmbedtls +kmod-tun
endef

define Package/warpq/description
 A small Cloudflare WARP client speaking the MASQUE (connect-ip) protocol over
 HTTP/2, exposed as a TUN device. Registers its own free WARP account, can bind
 a WARP+ licence key, and installs policy routing so all traffic leaves through
 the tunnel.
endef

define Package/warpq/conffiles
/etc/config/warpq
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src $(PKG_BUILD_DIR)/
	$(CP) ./Makefile.pkg $(PKG_BUILD_DIR)/Makefile
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Os -std=c99 -D_GNU_SOURCE -ffunction-sections -fdata-sections" \
		LDFLAGS="$(TARGET_LDFLAGS) -Wl,--gc-sections -Wl,-s"
endef

define Package/warpq/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/warpq $(1)/usr/sbin/warpq
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/warpq.init $(1)/etc/init.d/warpq
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/warpq.config $(1)/etc/config/warpq
endef

$(eval $(call BuildPackage,warpq))
