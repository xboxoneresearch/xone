// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Transport for the Marvell 88W8782U accessory radio built into Xbox One
 * consoles (USB 045e:02ce after firmware download, 1286:2040 in boot mode).
 *
 * The radio firmware runs a micro AP that beacons the Xbox Wireless element
 * itself and handles association. The host only configures the AP, toggles
 * pairing and exchanges GIP payloads with associated controllers.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/firmware.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "../bus/bus.h"

static ushort xone_mrvl_channel = 6;
MODULE_PARM_DESC(channel, "Operating channel of the accessory radio (default 6)");
module_param_named(channel, xone_mrvl_channel, ushort, 0444);

#define XONE_MRVL_VID_BOOT 0x1286
#define XONE_MRVL_PID_BOOT 0x2040
#define XONE_MRVL_VID 0x045e
#define XONE_MRVL_PID 0x02ce

#define XONE_MRVL_EP_CMD_OUT 0x01
#define XONE_MRVL_EP_CMD_IN 0x81
#define XONE_MRVL_EP_DATA_OUT 0x02
#define XONE_MRVL_EP_DATA_IN 0x82
#define XONE_MRVL_EP_DATA2_IN 0x83

#define XONE_MRVL_NUM_CMD_URBS 4
#define XONE_MRVL_NUM_DATA_URBS 8
#define XONE_MRVL_MAX_URBS_IN \
	(2 * XONE_MRVL_NUM_CMD_URBS + XONE_MRVL_NUM_DATA_URBS)
#define XONE_MRVL_LEN_IN 4096
#define XONE_MRVL_LEN_TX 2048

#define XONE_MRVL_MAX_CLIENTS 16
#define XONE_MRVL_CMD_TIMEOUT msecs_to_jiffies(2000)
#define XONE_MRVL_FW_TIMEOUT_MS 500
#define XONE_MRVL_PAIRING_TIMEOUT msecs_to_jiffies(60 * 1000)

#define XONE_MRVL_TYPE_CMD 0xf00dface
#define XONE_MRVL_TYPE_EVENT 0xbeefface

/* host command identifiers (mwifiex numbering where it exists) */
#define XONE_MRVL_CMD_RET_BIT 0x8000
#define XONE_MRVL_CMD_DOMAIN_INFO 0x005b
#define XONE_MRVL_CMD_KEY_MATERIAL 0x005e
#define XONE_MRVL_CMD_FUNC_INIT 0x00a9
#define XONE_MRVL_CMD_MAC_CONTROL 0x0028
#define XONE_MRVL_CMD_SYS_CONFIG 0x00b0
#define XONE_MRVL_CMD_BSS_START 0x00b1
#define XONE_MRVL_CMD_BSS_STOP 0x00b2
#define XONE_MRVL_CMD_RECONFIG_TX_BUF 0x00d9
#define XONE_MRVL_CMD_GET_HW_SPEC 0x0003
#define XONE_MRVL_CMD_MAC_REG_ACCESS 0x0019
#define XONE_MRVL_CMD_SUBSCRIBE_EVENT 0x0075
#define XONE_MRVL_CMD_DAWN 0x011a

#define XONE_MRVL_HOST_ACT_GET 0
#define XONE_MRVL_HOST_ACT_SET 1

/* command sequence field selects the interface: bss_type << 12 */
#define XONE_MRVL_BSS_UAP 0x1000

#define XONE_MRVL_MAC_CONTROL_DEFAULT 0x1011
#define XONE_MRVL_TX_BUF_SIZE 2048
#define XONE_MRVL_TLV_UAP_MAC 0x012b
#define XONE_MRVL_TLV_COUNTRY 0x0007
#define XONE_MRVL_TLV_KEY_MATERIAL 0x0100
#define XONE_MRVL_TLV_STA_MAC 0x0120

#define XONE_MRVL_KEY_TYPE_AES 2
#define XONE_MRVL_KEY_INFO_UNICAST BIT(1)
#define XONE_MRVL_KEY_INFO_ENABLED BIT(2)
#define XONE_MRVL_KEY_LEN 16
#define XONE_MRVL_MAX_TX_POWER_DBM 20

enum xone_mrvl_dawn_type {
	XONE_MRVL_DAWN_PAIRING = 1,
	XONE_MRVL_DAWN_FUTURE_CHANNELS = 4,
};

/* event cause in the low 16 bits; bss number and type above */
#define XONE_MRVL_EVT_ID GENMASK(15, 0)
#define XONE_MRVL_EVT_STA_DEAUTH 0x002c
#define XONE_MRVL_EVT_STA_ASSOC 0x002d

/*
 * uAP RX/TX descriptor packet types: GIP with an Ethernet-like header, or the
 * raw 802.11 data frame. The firmware delivers either form on receive.
 */
#define XONE_MRVL_PKT_TYPE_80211 1
#define XONE_MRVL_PKT_TYPE_GIP 3
#define XONE_MRVL_BSS_TYPE_UAP 1

/* firmware download block commands */
#define XONE_MRVL_FW_HAS_LAST_BLOCK 4
#define XONE_MRVL_FW_CMD_7 7

struct xone_mrvl_cmd_hdr {
	__le32 type;
	__le16 command;
	__le16 size;
	__le16 seq;
	__le16 result;
} __packed;

struct xone_mrvl_event_hdr {
	__le32 type;
	__le32 cause;
} __packed;

struct xone_mrvl_rxpd {
	u8 bss_type;
	u8 bss_num;
	__le16 pkt_length;
	__le16 pkt_offset;
	__le16 pkt_type;
} __packed;

struct xone_mrvl_txpd {
	u8 bss_type;
	u8 bss_num;
	__le16 pkt_length;
	__le16 pkt_offset;
	__le16 pkt_type;
	__le32 control;
	u8 priority;
	u8 flags;
	u8 delay;
	u8 reserved[5];
} __packed;

/* payload layout in both directions: destination, source, GIP length */
struct xone_mrvl_frame_hdr {
	u8 dest[ETH_ALEN];
	u8 src[ETH_ALEN];
	__be16 length;
} __packed;

#define XONE_MRVL_TX_HEADROOM \
	(sizeof(struct xone_mrvl_txpd) + sizeof(struct xone_mrvl_frame_hdr))

struct xone_mrvl_key_material {
	__le16 action;
	__le16 key_tlv_type;
	__le16 key_tlv_len;
	__le16 key_type;
	__le16 key_info;
	__le16 key_len;
	u8 key[XONE_MRVL_KEY_LEN];
	u8 key_index;
	__le16 mac_tlv_type;
	__le16 mac_tlv_len;
	u8 mac[ETH_ALEN];
} __packed;

struct xone_mrvl_fw_block_hdr {
	__le32 command;
	__le32 base;
	__le32 length;
	__le32 crc;
} __packed;

struct xone_mrvl_client {
	struct xone_mrvl *mrvl;
	u8 address[ETH_ALEN];
	struct gip_adapter *adapter;
};

struct xone_mrvl_tx {
	struct xone_mrvl *mrvl;
	u8 data[XONE_MRVL_LEN_TX];
};

enum xone_mrvl_event_type {
	XONE_MRVL_EVT_ADD_CLIENT,
	XONE_MRVL_EVT_REMOVE_CLIENT,
};

struct xone_mrvl_event {
	enum xone_mrvl_event_type type;
	struct xone_mrvl *mrvl;
	u8 address[ETH_ALEN];
	struct work_struct work;
};

struct xone_mrvl {
	struct usb_device *udev;
	struct usb_interface *intf;
	struct device *dev;

	u8 address[ETH_ALEN];

	/* serializes host commands; firmware accepts one at a time */
	struct mutex cmd_lock;
	/* protects the response fields below against the completion handler */
	spinlock_t cmd_state_lock;
	struct completion cmd_done;
	u16 cmd_expected;
	u16 cmd_expected_seq;
	u16 cmd_result;
	u8 cmd_seq;
	u8 *cmd_resp;
	int cmd_resp_len;
	int cmd_resp_max;

	struct urb *urbs_in[XONE_MRVL_MAX_URBS_IN];
	int num_urbs_in;
	struct usb_anchor urbs_out;
	/* set during teardown; no new TX urbs are submitted afterwards */
	bool stopping;

	/* serializes key changes against clearing them at unload */
	struct mutex key_lock;
	bool keys_cleared;

	/* serializes access to clients array */
	spinlock_t clients_lock;
	struct xone_mrvl_client *clients[XONE_MRVL_MAX_CLIENTS];

	struct workqueue_struct *event_wq;

	/* serializes pairing changes */
	struct mutex pairing_lock;
	struct delayed_work pairing_work;
	bool pairing;

	struct work_struct fw_work;
};

static void xone_mrvl_handle_cmd_resp(struct xone_mrvl *mrvl, u8 *data,
				      int len)
{
	struct xone_mrvl_cmd_hdr *hdr = (struct xone_mrvl_cmd_hdr *)data;
	int payload = len - (int)sizeof(*hdr);

	unsigned long flags;

	if (len < sizeof(*hdr))
		return;

	spin_lock_irqsave(&mrvl->cmd_state_lock, flags);

	if (le16_to_cpu(hdr->command) != mrvl->cmd_expected ||
	    le16_to_cpu(hdr->seq) != mrvl->cmd_expected_seq) {
		spin_unlock_irqrestore(&mrvl->cmd_state_lock, flags);
		dev_dbg(mrvl->dev, "%s: unexpected response 0x%04x seq 0x%04x\n",
			__func__, le16_to_cpu(hdr->command),
			le16_to_cpu(hdr->seq));
		return;
	}

	mrvl->cmd_result = le16_to_cpu(hdr->result);
	mrvl->cmd_resp_len = 0;
	if (mrvl->cmd_resp && payload > 0) {
		mrvl->cmd_resp_len = min(payload, mrvl->cmd_resp_max);
		memcpy(mrvl->cmd_resp, data + sizeof(*hdr), mrvl->cmd_resp_len);
	}

	/* only the first matching response completes the command */
	mrvl->cmd_expected = 0;
	complete(&mrvl->cmd_done);

	spin_unlock_irqrestore(&mrvl->cmd_state_lock, flags);
}

static int xone_mrvl_command(struct xone_mrvl *mrvl, u16 cmd, u16 bss,
			     const void *params, int len,
			     void *resp, int resp_max)
{
	struct xone_mrvl_cmd_hdr *hdr;
	unsigned long flags;
	u16 seq;
	int err, actual;

	hdr = kzalloc(sizeof(*hdr) + len, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	mutex_lock(&mrvl->cmd_lock);

	/* no responses arrive once the IN urbs are killed */
	if (READ_ONCE(mrvl->stopping)) {
		mutex_unlock(&mrvl->cmd_lock);
		kfree(hdr);
		return -ESHUTDOWN;
	}

	hdr->type = cpu_to_le32(XONE_MRVL_TYPE_CMD);
	hdr->command = cpu_to_le16(cmd);
	hdr->size = cpu_to_le16(sizeof(*hdr) - sizeof(hdr->type) + len);
	seq = ++mrvl->cmd_seq | bss;
	hdr->seq = cpu_to_le16(seq);
	if (len)
		memcpy(hdr + 1, params, len);

	reinit_completion(&mrvl->cmd_done);
	spin_lock_irqsave(&mrvl->cmd_state_lock, flags);
	mrvl->cmd_expected = cmd | XONE_MRVL_CMD_RET_BIT;
	mrvl->cmd_expected_seq = seq;
	mrvl->cmd_resp = resp;
	mrvl->cmd_resp_max = resp_max;
	mrvl->cmd_resp_len = 0;
	spin_unlock_irqrestore(&mrvl->cmd_state_lock, flags);

	err = usb_bulk_msg(mrvl->udev,
			   usb_sndbulkpipe(mrvl->udev, XONE_MRVL_EP_CMD_OUT),
			   hdr, sizeof(*hdr) + len, &actual, 1000);
	if (err) {
		dev_err(mrvl->dev, "%s: send 0x%04x failed: %d\n",
			__func__, cmd, err);
		goto err_unlock;
	}

	if (!wait_for_completion_timeout(&mrvl->cmd_done,
					 XONE_MRVL_CMD_TIMEOUT)) {
		dev_err(mrvl->dev, "%s: command 0x%04x timed out\n",
			__func__, cmd);
		err = -ETIMEDOUT;
		goto err_unlock;
	}

	if (mrvl->cmd_result) {
		dev_err(mrvl->dev, "%s: command 0x%04x failed: %u\n",
			__func__, cmd, mrvl->cmd_result);
		err = -EIO;
		goto err_unlock;
	}

	err = mrvl->cmd_resp_len;

err_unlock:
	spin_lock_irqsave(&mrvl->cmd_state_lock, flags);
	mrvl->cmd_expected = 0;
	mrvl->cmd_resp = NULL;
	spin_unlock_irqrestore(&mrvl->cmd_state_lock, flags);
	mutex_unlock(&mrvl->cmd_lock);
	kfree(hdr);

	return err;
}

static int xone_mrvl_set_dawn(struct xone_mrvl *mrvl,
			      enum xone_mrvl_dawn_type type,
			      const u8 *value, int len)
{
	u8 params[8] = {};

	if (len > sizeof(params) - 2)
		return -EINVAL;

	put_unaligned_le16(type, params);
	memcpy(params + 2, value, len);

	return xone_mrvl_command(mrvl, XONE_MRVL_CMD_DAWN, XONE_MRVL_BSS_UAP,
				 params, sizeof(params), NULL, 0);
}

static int xone_mrvl_set_pairing(struct xone_mrvl *mrvl, bool enable)
{
	u8 value[2] = { enable, 0 };
	int err = 0;

	mutex_lock(&mrvl->pairing_lock);

	if (mrvl->pairing == enable)
		goto out_unlock;

	err = xone_mrvl_set_dawn(mrvl, XONE_MRVL_DAWN_PAIRING,
				 value, sizeof(value));
	if (err < 0)
		goto out_unlock;

	err = 0;
	mrvl->pairing = enable;
	dev_dbg(mrvl->dev, "%s: enabled=%d\n", __func__, enable);

	if (enable)
		mod_delayed_work(system_wq, &mrvl->pairing_work,
				 XONE_MRVL_PAIRING_TIMEOUT);

out_unlock:
	mutex_unlock(&mrvl->pairing_lock);

	return err;
}

static void xone_mrvl_pairing_timeout(struct work_struct *work)
{
	struct xone_mrvl *mrvl = container_of(to_delayed_work(work),
					      typeof(*mrvl), pairing_work);
	int err;

	err = xone_mrvl_set_pairing(mrvl, false);
	if (err)
		dev_err(mrvl->dev, "%s: disable pairing failed: %d\n",
			__func__, err);
}

static ssize_t pairing_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct xone_mrvl *mrvl = usb_get_intfdata(to_usb_interface(dev));

	return sysfs_emit(buf, "%d\n", mrvl->pairing);
}

static ssize_t pairing_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct xone_mrvl *mrvl = usb_get_intfdata(to_usb_interface(dev));
	bool enable;
	int err;

	err = kstrtobool(buf, &enable);
	if (err)
		return err;

	err = xone_mrvl_set_pairing(mrvl, enable);
	if (err)
		return err;

	return count;
}

static DEVICE_ATTR_RW(pairing);

static struct attribute *xone_mrvl_attrs[] = {
	&dev_attr_pairing.attr,
	NULL,
};

static bool xone_mrvl_is_boot(struct usb_device *udev)
{
	return le16_to_cpu(udev->descriptor.idVendor) == XONE_MRVL_VID_BOOT;
}

/* the boot device has no command interface */
static umode_t xone_mrvl_attr_visible(struct kobject *kobj,
				      struct attribute *attr, int n)
{
	struct usb_interface *intf = to_usb_interface(kobj_to_dev(kobj));

	return xone_mrvl_is_boot(interface_to_usbdev(intf)) ? 0 : attr->mode;
}

static const struct attribute_group xone_mrvl_group = {
	.attrs = xone_mrvl_attrs,
	.is_visible = xone_mrvl_attr_visible,
};

static const struct attribute_group *xone_mrvl_groups[] = {
	&xone_mrvl_group,
	NULL,
};

static void xone_mrvl_complete_out(struct urb *urb)
{
	kfree(urb->context);
}

static int xone_mrvl_get_buffer(struct gip_adapter *adap,
				struct gip_adapter_buffer *buf)
{
	struct xone_mrvl_client *client = dev_get_drvdata(&adap->dev);
	struct xone_mrvl_tx *tx;

	tx = kzalloc(sizeof(*tx), GFP_ATOMIC);
	if (!tx)
		return -ENOMEM;

	tx->mrvl = client->mrvl;

	buf->context = tx;
	buf->data = tx->data + XONE_MRVL_TX_HEADROOM;
	buf->length = sizeof(tx->data) - XONE_MRVL_TX_HEADROOM;

	return 0;
}

static int xone_mrvl_submit_buffer(struct gip_adapter *adap,
				   struct gip_adapter_buffer *buf)
{
	struct xone_mrvl_client *client = dev_get_drvdata(&adap->dev);
	struct xone_mrvl *mrvl = client->mrvl;
	struct xone_mrvl_tx *tx = buf->context;
	struct xone_mrvl_txpd *txpd = (struct xone_mrvl_txpd *)tx->data;
	struct xone_mrvl_frame_hdr *hdr = (struct xone_mrvl_frame_hdr *)(txpd + 1);
	struct urb *urb;
	int err;

	if (buf->type != GIP_BUF_DATA) {
		kfree(tx);
		return -EOPNOTSUPP;
	}

	if (READ_ONCE(mrvl->stopping)) {
		kfree(tx);
		return -ESHUTDOWN;
	}

	ether_addr_copy(hdr->dest, client->address);
	ether_addr_copy(hdr->src, mrvl->address);
	hdr->length = cpu_to_be16(buf->length);

	txpd->bss_type = XONE_MRVL_BSS_TYPE_UAP;
	txpd->pkt_length = cpu_to_le16(sizeof(*hdr) + buf->length);
	txpd->pkt_offset = cpu_to_le16(sizeof(*txpd));
	txpd->pkt_type = cpu_to_le16(XONE_MRVL_PKT_TYPE_GIP);

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb) {
		kfree(tx);
		return -ENOMEM;
	}

	usb_fill_bulk_urb(urb, mrvl->udev,
			  usb_sndbulkpipe(mrvl->udev, XONE_MRVL_EP_DATA_OUT),
			  tx->data, XONE_MRVL_TX_HEADROOM + buf->length,
			  xone_mrvl_complete_out, tx);
	usb_anchor_urb(urb, &mrvl->urbs_out);

	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err) {
		usb_unanchor_urb(urb);
		kfree(tx);
	}

	usb_free_urb(urb);

	return err;
}

/* a NULL key removes the station key; the firmware keeps keys across FUNC_INIT */
static int xone_mrvl_set_key(struct xone_mrvl *mrvl, const u8 *addr,
			     const u8 *key)
{
	struct xone_mrvl_key_material params = {};
	u16 info = XONE_MRVL_KEY_INFO_UNICAST;
	int err;

	mutex_lock(&mrvl->key_lock);

	/* no key may outlive the driver; the next load would find it */
	if (key && mrvl->keys_cleared) {
		mutex_unlock(&mrvl->key_lock);
		return -ESHUTDOWN;
	}

	if (key) {
		info |= XONE_MRVL_KEY_INFO_ENABLED;
		memcpy(params.key, key, XONE_MRVL_KEY_LEN);
	}

	params.action = cpu_to_le16(XONE_MRVL_HOST_ACT_SET);
	params.key_tlv_type = cpu_to_le16(XONE_MRVL_TLV_KEY_MATERIAL);
	params.key_tlv_len = cpu_to_le16(offsetof(typeof(params), mac_tlv_type) -
					 offsetof(typeof(params), key_type));
	params.key_type = cpu_to_le16(XONE_MRVL_KEY_TYPE_AES);
	params.key_info = cpu_to_le16(info);
	params.key_len = cpu_to_le16(XONE_MRVL_KEY_LEN);
	params.mac_tlv_type = cpu_to_le16(XONE_MRVL_TLV_STA_MAC);
	params.mac_tlv_len = cpu_to_le16(ETH_ALEN);
	ether_addr_copy(params.mac, addr);

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_KEY_MATERIAL,
				XONE_MRVL_BSS_UAP, &params, sizeof(params),
				NULL, 0);
	mutex_unlock(&mrvl->key_lock);
	dev_dbg(mrvl->dev, "%s: address=%pM, enabled=%d, err=%d\n", __func__,
		addr, !!key, err);

	return err < 0 ? err : 0;
}

static int xone_mrvl_set_encryption_key(struct gip_adapter *adap,
					u8 *key, int len)
{
	struct xone_mrvl_client *client = dev_get_drvdata(&adap->dev);

	if (len != XONE_MRVL_KEY_LEN)
		return -EINVAL;

	return xone_mrvl_set_key(client->mrvl, client->address, key);
}

static struct gip_adapter_ops xone_mrvl_adapter_ops = {
	.get_buffer = xone_mrvl_get_buffer,
	.submit_buffer = xone_mrvl_submit_buffer,
	.set_encryption_key = xone_mrvl_set_encryption_key,
};

static struct xone_mrvl_client *
xone_mrvl_find_client(struct xone_mrvl *mrvl, const u8 *addr)
{
	int i;

	for (i = 0; i < XONE_MRVL_MAX_CLIENTS; i++)
		if (mrvl->clients[i] &&
		    ether_addr_equal(mrvl->clients[i]->address, addr))
			return mrvl->clients[i];

	return NULL;
}

/* only teardown is fatal; a stale key at worst costs the controller a rejoin */
static int xone_mrvl_clear_key(struct xone_mrvl *mrvl, const u8 *addr)
{
	int err = xone_mrvl_set_key(mrvl, addr, NULL);

	if (err == -ESHUTDOWN)
		return err;

	if (err)
		dev_warn(mrvl->dev, "%s: address=%pM, err=%d\n", __func__,
			 addr, err);

	return 0;
}

static int xone_mrvl_add_client(struct xone_mrvl *mrvl, const u8 *addr)
{
	struct xone_mrvl_client *client;
	unsigned long flags;
	int i, err;

	/* a new association starts unencrypted, also for a known client */
	if (xone_mrvl_find_client(mrvl, addr))
		return xone_mrvl_clear_key(mrvl, addr);

	for (i = 0; i < XONE_MRVL_MAX_CLIENTS; i++)
		if (!mrvl->clients[i])
			break;

	if (i == XONE_MRVL_MAX_CLIENTS)
		return -ENOSPC;

	err = xone_mrvl_clear_key(mrvl, addr);
	if (err)
		return err;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	client->mrvl = mrvl;
	ether_addr_copy(client->address, addr);

	client->adapter = gip_create_adapter(mrvl->dev,
					     &xone_mrvl_adapter_ops, 1);
	if (IS_ERR(client->adapter)) {
		err = PTR_ERR(client->adapter);

		kfree(client);
		return err;
	}

	dev_set_drvdata(&client->adapter->dev, client);

	spin_lock_irqsave(&mrvl->clients_lock, flags);
	mrvl->clients[i] = client;
	spin_unlock_irqrestore(&mrvl->clients_lock, flags);

	dev_dbg(mrvl->dev, "%s: address=%pM\n", __func__, addr);

	return 0;
}

static void xone_mrvl_remove_client(struct xone_mrvl *mrvl, const u8 *addr)
{
	struct xone_mrvl_client *client;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&mrvl->clients_lock, flags);

	for (i = 0; i < XONE_MRVL_MAX_CLIENTS; i++) {
		client = mrvl->clients[i];
		if (client && (!addr || ether_addr_equal(client->address, addr)))
			break;
	}

	if (i == XONE_MRVL_MAX_CLIENTS) {
		spin_unlock_irqrestore(&mrvl->clients_lock, flags);
		return;
	}

	mrvl->clients[i] = NULL;
	spin_unlock_irqrestore(&mrvl->clients_lock, flags);

	dev_dbg(mrvl->dev, "%s: address=%pM\n", __func__, client->address);

	gip_destroy_adapter(client->adapter);
	kfree(client);
}

static void xone_mrvl_remove_clients(struct xone_mrvl *mrvl)
{
	int i;

	for (i = 0; i < XONE_MRVL_MAX_CLIENTS; i++)
		xone_mrvl_remove_client(mrvl, NULL);
}

static void xone_mrvl_handle_event_work(struct work_struct *work)
{
	struct xone_mrvl_event *evt = container_of(work, typeof(*evt), work);
	int err = 0;

	switch (evt->type) {
	case XONE_MRVL_EVT_ADD_CLIENT:
		err = xone_mrvl_add_client(evt->mrvl, evt->address);
		break;
	case XONE_MRVL_EVT_REMOVE_CLIENT:
		xone_mrvl_remove_client(evt->mrvl, evt->address);
		break;
	}

	if (err)
		dev_err(evt->mrvl->dev, "%s: handle event failed: %d\n",
			__func__, err);

	kfree(evt);
}

static void xone_mrvl_queue_event(struct xone_mrvl *mrvl,
				  enum xone_mrvl_event_type type,
				  const u8 *addr)
{
	struct xone_mrvl_event *evt;

	evt = kzalloc(sizeof(*evt), GFP_ATOMIC);
	if (!evt)
		return;

	evt->type = type;
	evt->mrvl = mrvl;
	ether_addr_copy(evt->address, addr);
	INIT_WORK(&evt->work, xone_mrvl_handle_event_work);

	queue_work(mrvl->event_wq, &evt->work);
}

static void xone_mrvl_handle_event(struct xone_mrvl *mrvl, u8 *data, int len)
{
	struct xone_mrvl_event_hdr *hdr = (struct xone_mrvl_event_hdr *)data;
	/* STA events: u16 reason or flags, then the station address */
	u8 *addr = data + sizeof(*hdr) + 2;
	u32 cause;

	if (len < sizeof(*hdr) + 2 + ETH_ALEN)
		return;

	cause = le32_to_cpu(hdr->cause) & XONE_MRVL_EVT_ID;

	switch (cause) {
	case XONE_MRVL_EVT_STA_ASSOC:
		xone_mrvl_queue_event(mrvl, XONE_MRVL_EVT_ADD_CLIENT, addr);
		break;
	case XONE_MRVL_EVT_STA_DEAUTH:
		xone_mrvl_queue_event(mrvl, XONE_MRVL_EVT_REMOVE_CLIENT, addr);
		break;
	}
}

static void xone_mrvl_deliver(struct xone_mrvl *mrvl, const u8 *src,
			      void *gip, int len)
{
	struct xone_mrvl_client *client;
	unsigned long flags;

	spin_lock_irqsave(&mrvl->clients_lock, flags);

	client = xone_mrvl_find_client(mrvl, src);
	if (client)
		gip_process_buffer(client->adapter, gip, len);

	spin_unlock_irqrestore(&mrvl->clients_lock, flags);
}

static void xone_mrvl_handle_gip(struct xone_mrvl *mrvl, u8 *payload,
				 int length)
{
	struct xone_mrvl_frame_hdr *hdr = (struct xone_mrvl_frame_hdr *)payload;
	int gip_len;

	if (length < sizeof(*hdr))
		return;

	gip_len = be16_to_cpu(hdr->length);
	if (gip_len > length - (int)sizeof(*hdr))
		return;

	xone_mrvl_deliver(mrvl, hdr->src, hdr + 1, gip_len);
}

static void xone_mrvl_handle_80211(struct xone_mrvl *mrvl, u8 *frame,
				   int length)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)frame;
	int hdr_len = 24;
	__le16 fc;

	if (length < hdr_len)
		return;

	fc = hdr->frame_control;
	if (!ieee80211_is_data(fc)) {
		print_hex_dump_debug("xone-marvell mgmt: ", DUMP_PREFIX_OFFSET,
				     16, 1, frame, min(length, 64), false);
		return;
	}

	if (ieee80211_has_a4(fc))
		hdr_len += ETH_ALEN;

	if (ieee80211_is_data_qos(fc))
		hdr_len += IEEE80211_QOS_CTL_LEN;

	if (length < hdr_len)
		return;

	xone_mrvl_deliver(mrvl, hdr->addr2, frame + hdr_len, length - hdr_len);
}

static void xone_mrvl_handle_data(struct xone_mrvl *mrvl, u8 *data, int len)
{
	struct xone_mrvl_rxpd *rxpd = (struct xone_mrvl_rxpd *)data;
	int offset, length;

	if (len < sizeof(*rxpd))
		return;

	offset = le16_to_cpu(rxpd->pkt_offset);
	length = le16_to_cpu(rxpd->pkt_length);
	if (offset + length > len)
		return;

	switch (le16_to_cpu(rxpd->pkt_type)) {
	case XONE_MRVL_PKT_TYPE_GIP:
		xone_mrvl_handle_gip(mrvl, data + offset, length);
		break;
	case XONE_MRVL_PKT_TYPE_80211:
		xone_mrvl_handle_80211(mrvl, data + offset, length);
		break;
	default:
		print_hex_dump_debug("xone-marvell rx: ", DUMP_PREFIX_OFFSET,
				     16, 1, data, min(len, 128), false);
		break;
	}
}

static void xone_mrvl_complete_in(struct urb *urb)
{
	struct xone_mrvl *mrvl = urb->context;
	u8 *data = urb->transfer_buffer;
	int len = urb->actual_length;
	int err;

	switch (urb->status) {
	case 0:
		break;
	case -ENOENT:
	case -ECONNRESET:
	case -ESHUTDOWN:
		return;
	case -EPIPE:
	case -EPROTO:
	case -EILSEQ:
	case -ETIME:
	case -EOVERFLOW:
		dev_err_ratelimited(mrvl->dev, "%s: ep %u stopped: %d\n",
				    __func__, usb_pipeendpoint(urb->pipe),
				    urb->status);
		return;
	default:
		dev_dbg(mrvl->dev, "%s: ep %u status %d\n", __func__,
			usb_pipeendpoint(urb->pipe), urb->status);
		goto resubmit;
	}

	if (usb_pipeendpoint(urb->pipe) == (XONE_MRVL_EP_CMD_IN & 0x0f)) {
		if (len >= 4 &&
		    get_unaligned_le32(data) == XONE_MRVL_TYPE_CMD)
			xone_mrvl_handle_cmd_resp(mrvl, data, len);
		else if (len >= 4 &&
			 get_unaligned_le32(data) == XONE_MRVL_TYPE_EVENT)
			xone_mrvl_handle_event(mrvl, data, len);
	} else {
		xone_mrvl_handle_data(mrvl, data, len);
	}

resubmit:
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err && err != -ENODEV && err != -EPERM)
		dev_err(mrvl->dev, "%s: submit failed: %d\n", __func__, err);
}

/* the driver owns one reference to each RX urb until xone_mrvl_free_urbs_in */
static int xone_mrvl_init_urbs_in(struct xone_mrvl *mrvl, u8 ep, int count)
{
	struct urb *urb;
	void *buf;
	int i, err;

	for (i = 0; i < count; i++) {
		if (mrvl->num_urbs_in == XONE_MRVL_MAX_URBS_IN)
			return -ENOSPC;

		urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!urb)
			return -ENOMEM;

		buf = usb_alloc_coherent(mrvl->udev, XONE_MRVL_LEN_IN,
					 GFP_KERNEL, &urb->transfer_dma);
		if (!buf) {
			usb_free_urb(urb);
			return -ENOMEM;
		}

		usb_fill_bulk_urb(urb, mrvl->udev,
				  usb_rcvbulkpipe(mrvl->udev, ep), buf,
				  XONE_MRVL_LEN_IN, xone_mrvl_complete_in, mrvl);
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
		mrvl->urbs_in[mrvl->num_urbs_in++] = urb;

		err = usb_submit_urb(urb, GFP_KERNEL);
		if (err)
			return err;
	}

	return 0;
}

static void xone_mrvl_kill_urbs_in(struct xone_mrvl *mrvl)
{
	int i;

	for (i = 0; i < mrvl->num_urbs_in; i++)
		usb_kill_urb(mrvl->urbs_in[i]);
}

static void xone_mrvl_free_urbs_in(struct xone_mrvl *mrvl)
{
	struct urb *urb;
	int i;

	for (i = 0; i < mrvl->num_urbs_in; i++) {
		urb = mrvl->urbs_in[i];
		usb_free_coherent(mrvl->udev, XONE_MRVL_LEN_IN,
				  urb->transfer_buffer, urb->transfer_dma);
		usb_free_urb(urb);
	}

	mrvl->num_urbs_in = 0;
}

static int xone_mrvl_read_address(struct xone_mrvl *mrvl)
{
	__le16 action = cpu_to_le16(XONE_MRVL_HOST_ACT_GET);
	u8 *resp;
	int len, pos, err;

	resp = kzalloc(XONE_MRVL_LEN_IN, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	len = xone_mrvl_command(mrvl, XONE_MRVL_CMD_SYS_CONFIG,
				XONE_MRVL_BSS_UAP, &action, sizeof(action),
				resp, XONE_MRVL_LEN_IN);
	if (len < 0) {
		err = len;
		goto out_free;
	}

	/* response: u16 action, then TLVs of u16 type, u16 length, value */
	err = -ENOENT;
	for (pos = 2; pos + 4 <= len;) {
		u16 type = get_unaligned_le16(resp + pos);
		u16 tlv_len = get_unaligned_le16(resp + pos + 2);

		if (pos + 4 + tlv_len > len)
			break;

		if (type == XONE_MRVL_TLV_UAP_MAC && tlv_len == ETH_ALEN) {
			ether_addr_copy(mrvl->address, resp + pos + 4);
			err = 0;
			break;
		}

		pos += 4 + tlv_len;
	}

out_free:
	kfree(resp);

	return err;
}

static int xone_mrvl_set_domain(struct xone_mrvl *mrvl, u8 channel)
{
	/* this firmware uses 4-byte channel entries: first, count, power, disabled */
	u8 params[] = {
		XONE_MRVL_HOST_ACT_SET, 0x00,
		XONE_MRVL_TLV_COUNTRY, 0x00, 0x07, 0x00,
		'U', 'S', ' ',
		channel, 1, XONE_MRVL_MAX_TX_POWER_DBM, 0,
	};
	int err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_DOMAIN_INFO,
				XONE_MRVL_BSS_UAP, params, sizeof(params),
				NULL, 0);

	return err < 0 ? err : 0;
}

static int xone_mrvl_start_ap(struct xone_mrvl *mrvl)
{
	static const u8 mac_reg[] = { 0x00, 0x00, 0x88, 0x21, 0x2d, 0x00, 0x00, 0x00 };
	/* action 2 (bitwise set), event mask 0x0008, TLV 0x0107 { 0x1e, 0x00 } */
	static const u8 subscribe[] = {
		0x02, 0x00, 0x08, 0x00, 0x07, 0x01, 0x02, 0x00, 0x1e, 0x00,
	};
	u8 hw_spec[64] = {};
	u8 tx_buf[4], mac_ctrl[4];
	u8 channels[3] = { xone_mrvl_channel, xone_mrvl_channel,
			   xone_mrvl_channel };
	int err;

	put_unaligned_le16(XONE_MRVL_HOST_ACT_SET, tx_buf);
	put_unaligned_le16(XONE_MRVL_TX_BUF_SIZE, tx_buf + 2);
	put_unaligned_le32(XONE_MRVL_MAC_CONTROL_DEFAULT, mac_ctrl);

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_FUNC_INIT, 0, NULL, 0,
				NULL, 0);
	if (err < 0)
		return err;

	/* FUNC_INIT resets the configuration but leaves a running BSS up */
	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_BSS_STOP,
				XONE_MRVL_BSS_UAP, NULL, 0, NULL, 0);
	if (err < 0)
		return err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_GET_HW_SPEC, 0,
				hw_spec, sizeof(hw_spec), NULL, 0);
	if (err < 0)
		return err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_RECONFIG_TX_BUF, 0,
				tx_buf, sizeof(tx_buf), NULL, 0);
	if (err < 0)
		return err;

	/* register read and event subscription as sent by the console driver */
	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_MAC_REG_ACCESS, 0,
				mac_reg, sizeof(mac_reg), NULL, 0);
	if (err < 0)
		return err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_SUBSCRIBE_EVENT, 0,
				subscribe, sizeof(subscribe), NULL, 0);
	if (err < 0)
		return err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_MAC_CONTROL,
				XONE_MRVL_BSS_UAP, mac_ctrl, sizeof(mac_ctrl),
				NULL, 0);
	if (err < 0)
		return err;

	err = xone_mrvl_read_address(mrvl);
	if (err)
		return err;

	err = xone_mrvl_set_dawn(mrvl, XONE_MRVL_DAWN_FUTURE_CHANNELS,
				 channels, sizeof(channels));
	if (err < 0)
		return err;

	/* the firmware selects the start channel from the 802.11d list */
	err = xone_mrvl_set_domain(mrvl, xone_mrvl_channel);
	if (err)
		return err;

	err = xone_mrvl_command(mrvl, XONE_MRVL_CMD_BSS_START,
				XONE_MRVL_BSS_UAP, NULL, 0, NULL, 0);
	if (err < 0)
		return err;

	dev_info(mrvl->dev, "%s: address=%pM, channel=%u\n", __func__,
		 mrvl->address, xone_mrvl_channel);

	return 0;
}

static int xone_mrvl_fw_bulk(struct xone_mrvl *mrvl, void *out, int out_len,
			     void *in, int in_len)
{
	int err, actual;

	err = usb_bulk_msg(mrvl->udev,
			   usb_sndbulkpipe(mrvl->udev, XONE_MRVL_EP_CMD_OUT),
			   out, out_len, &actual, XONE_MRVL_FW_TIMEOUT_MS);
	if (err)
		return err;

	err = usb_bulk_msg(mrvl->udev,
			   usb_rcvbulkpipe(mrvl->udev, XONE_MRVL_EP_CMD_IN),
			   in, in_len, &actual, XONE_MRVL_FW_TIMEOUT_MS);

	return err ? err : actual;
}

static int xone_mrvl_download_fw(struct xone_mrvl *mrvl,
				 const struct firmware *fw)
{
	struct xone_mrvl_fw_block_hdr *blk;
	u8 *buf, *reply;
	size_t off = 0;
	u32 seq = 0, cmd, data_len;
	int err;

	buf = kzalloc(sizeof(*blk) + sizeof(__le32) + XONE_MRVL_LEN_TX,
		      GFP_KERNEL);
	reply = kzalloc(64, GFP_KERNEL);
	if (!buf || !reply) {
		err = -ENOMEM;
		goto out_free;
	}

	/* chip revision probe: 16 zero bytes, reply is not used */
	err = xone_mrvl_fw_bulk(mrvl, buf, 16, reply, 64);
	if (err < 0)
		goto out_free;

	while (off + sizeof(*blk) <= fw->size) {
		blk = (struct xone_mrvl_fw_block_hdr *)(fw->data + off);
		cmd = le32_to_cpu(blk->command);
		data_len = cmd == XONE_MRVL_FW_CMD_7 ? 0 :
			   le32_to_cpu(blk->length);

		if (off + sizeof(*blk) + data_len > fw->size ||
		    data_len > XONE_MRVL_LEN_TX) {
			err = -EINVAL;
			goto out_free;
		}

		/* block header, sequence number, data */
		memcpy(buf, blk, sizeof(*blk));
		put_unaligned_le32(seq, buf + sizeof(*blk));
		memcpy(buf + sizeof(*blk) + sizeof(__le32), blk + 1, data_len);

		err = xone_mrvl_fw_bulk(mrvl, buf,
					sizeof(*blk) + sizeof(__le32) + data_len,
					reply, 64);
		if (err < 0)
			goto out_free;

		if (err < 2 * sizeof(__le32)) {
			dev_err(mrvl->dev, "%s: block %u: short reply\n",
				__func__, seq);
			err = -EIO;
			goto out_free;
		}

		/* reply: u32 status (nonzero on CRC error), u32 sequence */
		if (get_unaligned_le32(reply) ||
		    get_unaligned_le32(reply + 4) != seq) {
			dev_err(mrvl->dev, "%s: block %u rejected\n",
				__func__, seq);
			err = -EIO;
			goto out_free;
		}

		off += sizeof(*blk) + data_len;
		seq++;

		if (cmd == XONE_MRVL_FW_HAS_LAST_BLOCK) {
			dev_info(mrvl->dev, "%s: %u blocks loaded\n",
				 __func__, seq);
			err = 0;
			goto out_free;
		}
	}

	err = -EINVAL;

out_free:
	kfree(reply);
	kfree(buf);

	return err;
}

static void xone_mrvl_fw_load(struct work_struct *work)
{
	struct xone_mrvl *mrvl = container_of(work, typeof(*mrvl), fw_work);
	const struct firmware *fw;
	char name[32];
	int err;

	snprintf(name, sizeof(name), "xone_marvell_%04x.bin", XONE_MRVL_PID);

	err = request_firmware(&fw, name, mrvl->dev);
	if (err) {
		dev_err(mrvl->dev, "%s: request %s failed: %d\n",
			__func__, name, err);
		return;
	}

	/* the device re-enumerates with the Xbox product ID afterwards */
	err = xone_mrvl_download_fw(mrvl, fw);
	if (err)
		dev_err(mrvl->dev, "%s: download failed: %d\n", __func__, err);

	release_firmware(fw);
}

static int xone_mrvl_probe_boot(struct xone_mrvl *mrvl)
{
	INIT_WORK(&mrvl->fw_work, xone_mrvl_fw_load);
	schedule_work(&mrvl->fw_work);

	return 0;
}

/*
 * Teardown order: block new TX, stop RX, let queued events finish, drop the
 * clients (which may still send), then reap TX urbs and free RX buffers.
 */
static void xone_mrvl_stop(struct xone_mrvl *mrvl)
{
	WRITE_ONCE(mrvl->stopping, true);
	xone_mrvl_kill_urbs_in(mrvl);
	destroy_workqueue(mrvl->event_wq);
	mrvl->event_wq = NULL;
	xone_mrvl_remove_clients(mrvl);
	usb_kill_anchored_urbs(&mrvl->urbs_out);
	xone_mrvl_free_urbs_in(mrvl);
}

static int xone_mrvl_probe_radio(struct xone_mrvl *mrvl)
{
	int err;

	if (!((xone_mrvl_channel >= 1 && xone_mrvl_channel <= 14) ||
	      (xone_mrvl_channel >= 36 && xone_mrvl_channel <= 165))) {
		dev_err(mrvl->dev, "%s: invalid channel %u\n", __func__,
			xone_mrvl_channel);
		return -EINVAL;
	}

	mrvl->event_wq = alloc_ordered_workqueue("xone_marvell", 0);
	if (!mrvl->event_wq)
		return -ENOMEM;

	err = xone_mrvl_init_urbs_in(mrvl, XONE_MRVL_EP_CMD_IN,
				     XONE_MRVL_NUM_CMD_URBS);
	if (!err)
		err = xone_mrvl_init_urbs_in(mrvl, XONE_MRVL_EP_DATA_IN,
					     XONE_MRVL_NUM_DATA_URBS);
	if (!err)
		err = xone_mrvl_init_urbs_in(mrvl, XONE_MRVL_EP_DATA2_IN,
					     XONE_MRVL_NUM_CMD_URBS);
	if (!err)
		err = xone_mrvl_start_ap(mrvl);

	if (err)
		xone_mrvl_stop(mrvl);

	return err;
}

static bool xone_mrvl_has_bulk_ep(struct usb_interface *intf, u8 addr)
{
	struct usb_host_interface *alt = intf->cur_altsetting;
	int i;

	for (i = 0; i < alt->desc.bNumEndpoints; i++)
		if (alt->endpoint[i].desc.bEndpointAddress == addr)
			return usb_endpoint_xfer_bulk(&alt->endpoint[i].desc);

	return false;
}

static bool xone_mrvl_check_endpoints(struct usb_interface *intf, bool boot)
{
	static const u8 boot_eps[] = { XONE_MRVL_EP_CMD_OUT, XONE_MRVL_EP_CMD_IN };
	static const u8 radio_eps[] = {
		XONE_MRVL_EP_CMD_OUT, XONE_MRVL_EP_CMD_IN,
		XONE_MRVL_EP_DATA_OUT, XONE_MRVL_EP_DATA_IN,
		XONE_MRVL_EP_DATA2_IN,
	};
	const u8 *eps = boot ? boot_eps : radio_eps;
	int i, count = boot ? ARRAY_SIZE(boot_eps) : ARRAY_SIZE(radio_eps);

	for (i = 0; i < count; i++)
		if (!xone_mrvl_has_bulk_ep(intf, eps[i]))
			return false;

	return true;
}

static int xone_mrvl_probe(struct usb_interface *intf,
			   const struct usb_device_id *id)
{
	struct xone_mrvl *mrvl;
	int err;

	if (intf->cur_altsetting->desc.bInterfaceNumber != 0)
		return -ENODEV;

	if (!xone_mrvl_check_endpoints(intf, xone_mrvl_is_boot(
			interface_to_usbdev(intf))))
		return -ENODEV;

	mrvl = devm_kzalloc(&intf->dev, sizeof(*mrvl), GFP_KERNEL);
	if (!mrvl)
		return -ENOMEM;

	mrvl->udev = interface_to_usbdev(intf);
	mrvl->intf = intf;
	mrvl->dev = &intf->dev;

	mutex_init(&mrvl->cmd_lock);
	spin_lock_init(&mrvl->cmd_state_lock);
	init_completion(&mrvl->cmd_done);
	init_usb_anchor(&mrvl->urbs_out);
	spin_lock_init(&mrvl->clients_lock);
	mutex_init(&mrvl->pairing_lock);
	mutex_init(&mrvl->key_lock);
	INIT_DELAYED_WORK(&mrvl->pairing_work, xone_mrvl_pairing_timeout);

	usb_set_intfdata(intf, mrvl);

	if (xone_mrvl_is_boot(mrvl->udev))
		return xone_mrvl_probe_boot(mrvl);

	err = xone_mrvl_probe_radio(mrvl);
	if (err)
		usb_set_intfdata(intf, NULL);

	return err;
}

/*
 * The firmware keeps station keys across FUNC_INIT. A key left behind for a
 * controller that rejoins after a reload stops all data from it.
 */
static void xone_mrvl_clear_keys(struct xone_mrvl *mrvl)
{
	u8 addrs[XONE_MRVL_MAX_CLIENTS][ETH_ALEN];
	unsigned long flags;
	int i, err, count = 0;

	mutex_lock(&mrvl->key_lock);
	mrvl->keys_cleared = true;
	mutex_unlock(&mrvl->key_lock);

	/* clients added by queued association events are cleared as well */
	flush_workqueue(mrvl->event_wq);

	spin_lock_irqsave(&mrvl->clients_lock, flags);
	for (i = 0; i < XONE_MRVL_MAX_CLIENTS; i++)
		if (mrvl->clients[i])
			ether_addr_copy(addrs[count++], mrvl->clients[i]->address);
	spin_unlock_irqrestore(&mrvl->clients_lock, flags);

	for (i = 0; i < count; i++) {
		err = xone_mrvl_set_key(mrvl, addrs[i], NULL);
		if (err) {
			dev_warn(mrvl->dev, "%s: address=%pM, err=%d\n",
				 __func__, addrs[i], err);
			break;
		}
	}
}

static void xone_mrvl_disconnect(struct usb_interface *intf)
{
	struct xone_mrvl *mrvl = usb_get_intfdata(intf);

	if (!mrvl)
		return;

	if (xone_mrvl_is_boot(mrvl->udev)) {
		cancel_work_sync(&mrvl->fw_work);
		usb_set_intfdata(intf, NULL);
		return;
	}

	cancel_delayed_work_sync(&mrvl->pairing_work);

	/*
	 * Stop the BSS while the IN pipes are still drained. Controllers keep
	 * sending to a running BSS, and once nothing reads the IN pipes the
	 * firmware stalls until the next power cycle.
	 */
	if (mrvl->udev->state != USB_STATE_NOTATTACHED) {
		xone_mrvl_clear_keys(mrvl);
		xone_mrvl_command(mrvl, XONE_MRVL_CMD_BSS_STOP,
				  XONE_MRVL_BSS_UAP, NULL, 0, NULL, 0);
	}

	xone_mrvl_stop(mrvl);
	usb_set_intfdata(intf, NULL);
}

static const struct usb_device_id xone_mrvl_id_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(XONE_MRVL_VID_BOOT, XONE_MRVL_PID_BOOT,
					USB_CLASS_VENDOR_SPEC,
					USB_SUBCLASS_VENDOR_SPEC, 0xff) },
	{ USB_DEVICE_AND_INTERFACE_INFO(XONE_MRVL_VID, XONE_MRVL_PID,
					USB_CLASS_VENDOR_SPEC,
					USB_SUBCLASS_VENDOR_SPEC, 0xff) },
	{},
};

static struct usb_driver xone_mrvl_driver = {
	.name = "xone-marvell",
	.probe = xone_mrvl_probe,
	.disconnect = xone_mrvl_disconnect,
	.id_table = xone_mrvl_id_table,
	.dev_groups = xone_mrvl_groups,
	/* disconnect stops the BSS, which needs working endpoints */
	.soft_unbind = 1,
};

module_usb_driver(xone_mrvl_driver);

MODULE_DEVICE_TABLE(usb, xone_mrvl_id_table);
MODULE_DESCRIPTION("xone Marvell 88W8782U accessory radio driver");
MODULE_LICENSE("GPL");
