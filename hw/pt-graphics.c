/*
 * graphics passthrough
 */

#include "pass-through.h"
#include "pci.h"
#include "pci/header.h"
#include "pci/pci.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>

extern int gfx_passthru;
extern int igd_passthru;

static uint32_t igd_guest_opregion = 0;

static int pch_map_irq(PCIDevice *pci_dev, int irq_num)
{
    PT_LOG("pch_map_irq called\n");
    return irq_num;
}

void intel_pch_init(PCIBus *bus)
{
    uint16_t vid, did;
    uint8_t  rid;
    struct pci_dev *pci_dev_1f;

    if ( !gfx_passthru )
        return;

    if ( !(pci_dev_1f=pt_pci_get_dev(0, 0x1f, 0)) )
    {
        PT_ERR("Error: Can't get pci_dev_host_bridge\n");
        abort();
    }

    vid = pt_pci_host_read(pci_dev_1f, PCI_VENDOR_ID, 2);
    did = pt_pci_host_read(pci_dev_1f, PCI_DEVICE_ID, 2);
    rid = pt_pci_host_read(pci_dev_1f, PCI_REVISION, 1);

    if (vid == PCI_VENDOR_ID_INTEL) {
        pci_isa_bridge_init(bus, PCI_DEVFN(0x1f, 0), vid, did, rid,
                            pch_map_irq, "intel_bridge_1f");

    }
}

uint32_t igd_read_opregion(struct pt_dev *pci_dev)
{
    uint32_t val = -1;

    if ( igd_guest_opregion == 0 )
        return -1;

    val = igd_guest_opregion;
#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG_DEV((PCIDevice*)pci_dev, "addr=%x len=%x val=%x\n",
            PCI_INTEL_OPREGION, 4, val);
#endif
    return val;
}

void igd_write_opregion(struct pt_dev *real_dev, uint32_t val)
{
    uint32_t host_opregion = 0;
    int ret;

    if ( igd_guest_opregion )
    {
        PT_LOG("opregion register already been set, ignoring %x\n", val);
        return;
    }

    host_opregion = pt_pci_host_read(real_dev->pci_dev, PCI_INTEL_OPREGION, 4);
    igd_guest_opregion = (val & ~0xfff) | (host_opregion & 0xfff);
    PT_LOG("Map OpRegion: %x -> %x\n", host_opregion, igd_guest_opregion);

    ret = xc_domain_memory_mapping(xc_handle, domid,
            igd_guest_opregion >> XC_PAGE_SHIFT,
            host_opregion >> XC_PAGE_SHIFT,
            3,
            DPCI_ADD_MAPPING);

    if ( ret != 0 )
    {
        PT_LOG("Error: Can't map opregion\n");
        igd_guest_opregion = 0;
    }
#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG_DEV((PCIDevice*)real_dev, "addr=%x len=%lx val=%x\n",
            PCI_INTEL_OPREGION, len, val);
#endif

}

void igd_pci_write(PCIDevice *pci_dev, uint32_t config_addr, uint32_t val, int len)
{
    struct pci_dev *pci_dev_host_bridge;
    assert(pci_dev->devfn == 0x00);
    if ( !igd_passthru )
        goto write_default;

    switch (config_addr)
    {
        case 0x58:        // PAVPC Offset
            break;
        default:
            goto write_default;
    }

    /* Host write */
    if ( !(pci_dev_host_bridge = pt_pci_get_dev(0, 0, 0)) )
    {
        PT_ERR("Error: Can't get pci_dev_host_bridge\n");
        abort();
    }

    pt_pci_host_write(pci_dev_host_bridge, config_addr, val, len);
#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG_DEV(pci_dev, "addr=%x len=%x val=%x\n",
               config_addr, len, val);
#endif
    return;

write_default:
    pci_default_write_config(pci_dev, config_addr, val, len);
}

uint32_t igd_pci_read(PCIDevice *pci_dev, uint32_t config_addr, int len)
{
    struct pci_dev *pci_dev_host_bridge;
    uint32_t val;

    assert(pci_dev->devfn == 0x00);
    if ( !igd_passthru )
        goto read_default;

    switch (config_addr)
    {
        case 0x00:        /* vendor id */
        case 0x02:        /* device id */
        case 0x08:        /* revision id */
        case 0x2c:        /* sybsystem vendor id */
        case 0x2e:        /* sybsystem id */
        case 0x50:        /* SNB: processor graphics control register */
        case 0x52:        /* processor graphics control register */
        case 0xa0:        /* top of memory */
        case 0xb0:        /* ILK: BSM: should read from dev 2 offset 0x5c */
        case 0x58:        /* SNB: PAVPC Offset */
        case 0xb4:        /* SNB: graphics base of stolen memory */
        case 0xb8:        /* SNB: base of GTT stolen memory */
            break;
        default:
            goto read_default;
    }

    /* Host read */
    if ( !(pci_dev_host_bridge = pt_pci_get_dev(0, 0, 0)) )
    {
        PT_ERR("Error: Can't get pci_dev_host_bridge\n");
        abort();
    }

    val = pt_pci_host_read(pci_dev_host_bridge, config_addr, len);
#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG_DEV(pci_dev, "addr=%x len=%x val=%x\n",
               config_addr, len, val);
#endif
    return val;
   
read_default:
   
   return pci_default_read_config(pci_dev, config_addr, len);
}

/*
 * register VGA resources for the domain with assigned gfx
 */
int register_vga_regions(struct pt_dev *real_device)
{
    int ret = 0;

    return ret;
}

/*
 * unregister VGA resources for the domain with assigned gfx
 */
int unregister_vga_regions(struct pt_dev *real_device)
{
    u32 vendor_id;
    int ret = 0;

    if ( !gfx_passthru || real_device->pci_dev->device_class != 0x0300 )
        return ret;

    vendor_id = pt_pci_host_read(real_device->pci_dev, PCI_VENDOR_ID, 2);
    if ( (vendor_id == PCI_VENDOR_ID_INTEL) && igd_guest_opregion )
    {
        ret |= xc_domain_memory_mapping(xc_handle, domid,
                igd_guest_opregion >> XC_PAGE_SHIFT,
                igd_guest_opregion >> XC_PAGE_SHIFT,
                3,
                DPCI_REMOVE_MAPPING);
    }

    if ( ret != 0 )
        PT_LOG("VGA region unmapping failed\n");

    return ret;
}

int setup_vga_pt(struct pt_dev *real_device)
{
    int rc = 0;

    if ( !gfx_passthru || real_device->pci_dev->device_class != 0x0300 )
        return rc;

    real_device->dev.config[0xa] = 0x80;

    return rc;
}
