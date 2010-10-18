/*
 * OMAP 35xx control module pad configuration (aka cmpc) driver
 *
 * Frank Agius <fgius@irobot.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/*
 * Derived from the mux driver code by Scott Ellis.
 * This driver can set configure the control module configuration register on the
 * OMAP 35xx processor.  This allow setting the the mode (from mode 0 to mode 7
 * for individual pins.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <mach/gpio.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <plat/mux.h>
#include <linux/gpio.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/notifier.h>
#include <linux/stddef.h>


#define OMAP34XX_PADCONF_START	0x48002030
#define OMAP34XX_PADCONF_SIZE	0x05cc
#define MAX_GPIO 		192 /* (OMAP34XX_NR_GPIOS * 32) */  


/*
 * IEN  - Input Enable
 * IDIS - Input Disable
 * PTD  - Pull type Down
 * PTU  - Pull type Up
 * DIS  - Pull type selection is inactive
 * EN   - Pull type selection is active
 * M0   - Mode 0
 */
#define IEN     (1 << 8)
#define IDIS    (0 << 8)
#define PTU     (1 << 4)
#define PTD     (0 << 4)
#define EN      (1 << 3)
#define DIS     (0 << 3)

static int gp_map[MAX_GPIO];
static int alt_map[MAX_GPIO];

#define GPIO_OE_REG_OFFSET	0x0034
#define OMAP34XX_GPIO1_BASE	0x48310000
#define OMAP34XX_GPIO2_BASE	0x49050000
#define OMAP34XX_GPIO3_BASE	0x49052000
#define OMAP34XX_GPIO4_BASE	0x49054000
#define OMAP34XX_GPIO5_BASE	0x49056000
#define OMAP34XX_GPIO6_BASE	0x49058000
#define PREFIX "cmpc: "


static int gpio_bank[6] =
{
  OMAP34XX_GPIO1_BASE,
  OMAP34XX_GPIO2_BASE,
  OMAP34XX_GPIO3_BASE,
  OMAP34XX_GPIO4_BASE,
  OMAP34XX_GPIO5_BASE,
  OMAP34XX_GPIO6_BASE
};


unsigned long pin;
int new_mode;

static void init_gpio_padconf_mapping(void);
void parse_input(char* first, char* last);

struct cmpc_dev
{
  dev_t devt;
  struct semaphore sem;
  struct cdev cdev;
  struct class *class;
};

static struct cmpc_dev cmpc_dev;


/* parse input */
void parse_input(char* first, char* last) {
  char* p;
  char* a;
  char* b;
  int rc = 0;
  int requested_mode;
  char buffer[128];

  printk(KERN_DEBUG PREFIX "handle input \n");
  for (p = first; p != last; ++p) {
    *p = toupper(*p);
  }

  /* valid commands are of the type "121:2" "176:4", on separate lines,
  ** where the first number is the pin, the second number is the mode (0=Mode 0, 1=Mode
  ** 1 etc */
  a = first;
  pin = simple_strtol(first, &a, 10);
  if (a == first) {
    rc = -1;
  };

  /* skip colon */
  if (*a == ':')
  {
    ++a;
  }
  else
  {
    rc = -1;
  }

  /* check for signed number */
  b = a;
  requested_mode = simple_strtol(b, &b, 10);
  if (a == b)
  {
    rc = -1;
  }
  else
  {
    if (0 <= requested_mode && requested_mode <= 7)
    {
      new_mode = requested_mode;
    }
    else
    {
      new_mode = 0;
      rc = -1;
    }
  }

  if (!rc)
  {
    printk(KERN_DEBUG PREFIX "Set pin %ld to mode %d\n", pin, new_mode);
  }
  else
  {
    strncpy(buffer, first, last - first);
    printk(KERN_ERR PREFIX "input parse failure: %s\n", buffer);
  }
}


static ssize_t cmpc_write(struct file *filp, const char __user *buff,
	size_t count, loff_t *offp)
{
  unsigned int reg, bank, bit;
  ssize_t status;
  size_t len;
  char buffer[128];
  void __iomem *base;
  char *p;
  char *first;
  char *last;

  if (count < 1)
    return 0;

  if (down_interruptible(&cmpc_dev.sem))
    return -ERESTARTSYS;

  memset(buffer, 0, sizeof(buffer));
  len = (count > 127) ? 127 : count;

	if (copy_from_user(buffer, buff, len)) {
		status = -EFAULT;
		goto cmpc_write_done;
	}

        /* split into strings */
        first = buffer;
        last = buffer;
        while (*first != 0) {
          while (*last != '\n' && *last != 0) {
            ++last;
          }
          if (first != last) {
            parse_input(first, last);
          }
          first = last;
          if (first != 0) {
            ++first;
            ++last;
          }
        }

	pin = simple_strtoul(buffer, &p, 10);

	if (p == buff)
        {
          printk(KERN_ALERT PREFIX "Input a PIN number\n");
          status = -EINVAL;
          goto cmpc_write_done;
	}

	if (pin >= MAX_GPIO || gp_map[pin] < 0)
        {
          printk(KERN_ALERT PREFIX "pin %lu is not available\n", pin);
          status = -EINVAL;
          goto cmpc_write_done;
	}

	base = ioremap(OMAP34XX_PADCONF_START, OMAP34XX_PADCONF_SIZE);

	if (base) {
		reg = ioread16(base + gp_map[pin]);
                // set to mode requested
                iowrite16((reg&0xff0)|new_mode, base + gp_map[pin]);
                // if the mode requested is gpio (mode 4), set direction to
                // output
                if (new_mode == 4)
                {
                  int rc=0;
                  rc=gpio_request(pin, "CMPC");
                  if (rc)
                  {
                    if (rc != -16)
                      printk(KERN_ERR PREFIX "gpio_request failed for pin %ld \n", pin);
                  }
                  gpio_direction_output(pin, 0);
                  // free the pin
                  gpio_free(pin);
                }
                // read the new pin state
		reg = ioread16(base + gp_map[pin]);
		printk(KERN_ALERT PREFIX "0x%lx  PIN %lu (0x%04x) : %s | %s | %s | M%u\n",
			(unsigned long) OMAP34XX_PADCONF_START + gp_map[pin],
			 pin, reg,
			reg & IEN ? "IEN" : "IDIS",
			reg & PTU ? "PTU" : "PTD",
			reg & EN ? "EN" : "DIS",
			reg & 0x0007);

		if (alt_map[pin] > 0) {
			reg = ioread16(base + alt_map[pin]);

			printk(KERN_ALERT PREFIX "0x%lx  PIN %lu (0x%04x) : %s | %s | %s | M%u\n",
				(unsigned long) OMAP34XX_PADCONF_START + alt_map[pin],
				pin, reg,
				reg & IEN ? "IEN" : "IDIS",
				reg & PTU ? "PTU" : "PTD",
				reg & EN ? "EN" : "DIS",
				reg & 0x0007);
		}

		iounmap(base);

		bank = pin >> 5;
		bit = pin & 0x001f;

		base = ioremap(gpio_bank[bank], 1024);

		if (base) {
			reg = ioread32(base + GPIO_OE_REG_OFFSET);

			printk(KERN_ALERT PREFIX "0x%0x  GPIO_OE[%u] : 0x%08X bit %u is %s\n",
				gpio_bank[bank] + GPIO_OE_REG_OFFSET,
				bank,
				reg,
				bit,
				reg & (1 << bit) ? "ON (input)" : "OFF (output)");

			iounmap(base);
		}
		else {
			printk(KERN_ALERT PREFIX "ioremap(GPIO_OE) failed\n");
			status = -EIO;
			goto cmpc_write_done;
		}
	}
	else
        {
		printk(KERN_ALERT PREFIX "ioremap(PADCONF) failed\n");
		status = -EIO;
		goto cmpc_write_done;
	}

	status = count;

cmpc_write_done:

	up(&cmpc_dev.sem);
	return status;
}

static struct file_operations cmpc_fops =
{
  .owner = THIS_MODULE,
  .write = cmpc_write,
};

static int __init cmpc_init_cdev(void)
{
  int error;

  cmpc_dev.devt = MKDEV(0, 0);
  error = alloc_chrdev_region(&cmpc_dev.devt, 0, 1, "cmpc");

  if (error < 0)
  {
    printk(KERN_ALERT PREFIX
      "alloc_chrdev_region() failed: error = %d \n", error);
    return -1;
  }

  cdev_init(&cmpc_dev.cdev, &cmpc_fops);
  cmpc_dev.cdev.owner = THIS_MODULE;

  error = cdev_add(&cmpc_dev.cdev, cmpc_dev.devt, 1);
  if (error)
  {
    printk(KERN_ALERT PREFIX "cdev_add() failed: error = %d\n", error);
    cdev_del(&cmpc_dev.cdev);
    return -1;
  }

  return 0;
}

static int __init cmpc_init_class(void)
{
  cmpc_dev.class = class_create(THIS_MODULE, "cmpc");

  if (!cmpc_dev.class)
  {
    printk(KERN_ALERT PREFIX "class_create() failed\n");
    return -1;
  }

  if (!device_create(cmpc_dev.class, NULL, cmpc_dev.devt, NULL, "cmpc"))
  {
    class_destroy(cmpc_dev.class);
    return -1;
  }

  return 0;
}

static int __init cmpc_init(void)
{
  memset(&cmpc_dev, 0, sizeof(struct cmpc_dev));
  sema_init(&cmpc_dev.sem, 1);

  if (cmpc_init_cdev())
    return -1;

  if (cmpc_init_class())
  {
    cdev_del(&cmpc_dev.cdev);
    unregister_chrdev_region(cmpc_dev.devt, 1);
    return -1;
  }

  init_gpio_padconf_mapping();
  return 0;
}

static void __exit cmpc_exit(void)
{
  device_destroy(cmpc_dev.class, cmpc_dev.devt);
  class_destroy(cmpc_dev.class);
  cdev_del(&cmpc_dev.cdev);
  unregister_chrdev_region(cmpc_dev.devt, 1);
}


static void init_gpio_padconf_mapping(void)
{
  int i;

  for (i = 0; i < MAX_GPIO; i++)
  {
    gp_map[i] = 0;
    alt_map[i] = 0;
  }

  gp_map[0] = 0x21E0;
  gp_map[12] = 0x25D8;
  gp_map[13] = 0x25DA;
  gp_map[14] = 0x25DC;
  gp_map[15] = 0x25DE;
  gp_map[16] = 0x25E0;
  gp_map[17] = 0x25E2;
  gp_map[18] = 0x25E4;
  gp_map[19] = 0x25E6;
  gp_map[20] = 0x25E8;
  gp_map[21] = 0x25EA;
  gp_map[22] = 0x25EC;
  gp_map[23] = 0x25EE;
  gp_map[24] = 0x25F0;
  gp_map[25] = 0x25F2;
  gp_map[26] = 0x25F4;
  gp_map[27] = 0x25F6;
  gp_map[28] = 0x25F8;
  gp_map[29] = 0x25FA;
  gp_map[34] = 0x207A;
  gp_map[35] = 0x207C;
  gp_map[36] = 0x207E;
  gp_map[37] = 0x2080;
  gp_map[38] = 0x2082;
  gp_map[39] = 0x2084;
  gp_map[40] = 0x2086;
  gp_map[41] = 0x2088;
  gp_map[42] = 0x208A;
  gp_map[43] = 0x208C;
  gp_map[44] = 0x209A;
  gp_map[45] = 0x20A0;
  gp_map[46] = 0x20A2;
  gp_map[47] = 0x20A4;
  gp_map[48] = 0x20A6;
  gp_map[49] = 0x20A8;
  gp_map[50] = 0x20AA;
  gp_map[51] = 0x20AC;
  gp_map[52] = 0x20B0;
  gp_map[53] = 0x20B2;
  gp_map[54] = 0x20B4;
  gp_map[55] = 0x20B6;
  gp_map[56] = 0x20B8;
  gp_map[57] = 0x20BA;
  gp_map[58] = 0x20BC;
  gp_map[59] = 0x20BE;
  gp_map[60] = 0x20C6;
  gp_map[61] = 0x20C8;
  gp_map[62] = 0x20CA;
  gp_map[63] = 0x20CE;
  gp_map[64] = 0x20D0;
  gp_map[65] = 0x20D2;
  gp_map[66] = 0x20D4;
  gp_map[67] = 0x20D6;
  gp_map[68] = 0x20D8;
  gp_map[69] = 0x20DA;
  gp_map[70] = 0x20DC;
  gp_map[71] = 0x20DE;
  gp_map[72] = 0x20E0;
  gp_map[73] = 0x20E2;
  gp_map[74] = 0x20E4;
  gp_map[75] = 0x20E6;
  gp_map[76] = 0x20E8;
  gp_map[77] = 0x20EA;
  gp_map[78] = 0x20EC;
  gp_map[79] = 0x20EE;
  gp_map[80] = 0x20F0;
  gp_map[81] = 0x20F2;
  gp_map[82] = 0x20F4;
  gp_map[83] = 0x20F6;
  gp_map[84] = 0x20F8;
  gp_map[85] = 0x20FA;
  gp_map[86] = 0x20FC;
  gp_map[87] = 0x20FE;
  gp_map[88] = 0x2100;
  gp_map[89] = 0x2102;
  gp_map[90] = 0x2104;
  gp_map[91] = 0x2106;
  gp_map[92] = 0x2108;
  gp_map[93] = 0x210A;
  gp_map[94] = 0x210C;
  gp_map[95] = 0x210E;
  gp_map[96] = 0x2110;
  gp_map[97] = 0x2112;
  gp_map[98] = 0x2114;
  gp_map[99] = 0x2116;
  gp_map[100] = 0x2118;
  gp_map[101] = 0x211A;
  gp_map[102] = 0x211C;
  gp_map[103] = 0x211E;
  gp_map[104] = 0x2120;
  gp_map[105] = 0x2122;
  gp_map[106] = 0x2124;
  gp_map[107] = 0x2126;
  gp_map[108] = 0x2128;
  gp_map[109] = 0x212A;
  gp_map[110] = 0x212C;
  gp_map[111] = 0x212E;
  gp_map[112] = 0x2134;
  gp_map[113] = 0x2136;
  gp_map[114] = 0x2138;
  gp_map[115] = 0x213A;
  gp_map[116] = 0x213C;
  gp_map[117] = 0x213E;
  gp_map[118] = 0x2140;
  gp_map[119] = 0x2142;
  gp_map[120] = 0x2144;  /* MMC1_CLK */
  alt_map[120] = 0x21A2; /* UART3_TX_IRTX */
  gp_map[121] = 0x2146;  /* MMC1_CMD */
  alt_map[121] = 0x21A4; /* HSUSB0_STP */
  gp_map[122] = 0x2148;  /* MMC1_DAT0 */
  alt_map[122] = 0x21A6; /* HSUSB0_DIR */
  gp_map[123] = 0x214A;
  gp_map[124] = 0x214C;  /* MMC1_DAT2 */
  alt_map[124] = 0x21A8; /* HSUSB0_NXT */
  gp_map[125] = 0x214E;  /* MMC1_DAT3 */
  alt_map[125] = 0x21AA; /* HSUSB0_DAT0 */
  gp_map[126] = 0x2150;  /* CAM_STROBE */
  alt_map[126] = 0x2132; /* MMC1_DAT4 */ 
  gp_map[127] = 0x2152;
  gp_map[128] = 0x2154;
  gp_map[129] = 0x2156;
  gp_map[130] = 0x2158;  /* MMC2_CLK */
  alt_map[130] = 0x21AC; /* HSUSB0_DATA1 */
  gp_map[131] = 0x215A;  /* MMC2_CMD */
  alt_map[131] = 0x21AE; /* HSUSB0_DATA2 */
  gp_map[132] = 0x215C;
  gp_map[133] = 0x215E;
  gp_map[134] = 0x2160;
  gp_map[135] = 0x2162;
  gp_map[136] = 0x2164;
  gp_map[137] = 0x2166;
  gp_map[138] = 0x2168;
  gp_map[139] = 0x216A;
  gp_map[140] = 0x216C;
  gp_map[141] = 0x216E;
  gp_map[142] = 0x2170;
  gp_map[143] = 0x2172;
  gp_map[144] = 0x2174;
  gp_map[145] = 0x2176;
  gp_map[146] = 0x2178;
  gp_map[147] = 0x217A;
  gp_map[148] = 0x217C;
  gp_map[149] = 0x217E;
  gp_map[150] = 0x2180;
  gp_map[151] = 0x2182;
  gp_map[152] = 0x2184;
  gp_map[153] = 0x2186;
  gp_map[154] = 0x2188;
  gp_map[155] = 0x218A;
  gp_map[156] = 0x218C;
  gp_map[157] = 0x218E;
  gp_map[158] = 0x2190;
  gp_map[159] = 0x2192;
  gp_map[160] = 0x2194;
  gp_map[161] = 0x2196;
  gp_map[162] = 0x2198;
  gp_map[163] = 0x219A;
  gp_map[164] = 0x219C;
  gp_map[165] = 0x219E;
  gp_map[166] = 0x21A0;
  gp_map[167] = 0x2130;
  gp_map[168] = 0x21BA;
  gp_map[169] = 0x21B0;
  gp_map[170] = 0x21C6;
  gp_map[171] = 0x21C8;
  gp_map[172] = 0x21CA;
  gp_map[173] = 0x21CC;
  gp_map[174] = 0x21CE;
  gp_map[175] = 0x21D0;
  gp_map[176] = 0x21D2;
  gp_map[177] = 0x21D4;
  gp_map[178] = 0x21D6;
  gp_map[179] = 0x21D8;
  gp_map[180] = 0x21DA;
  gp_map[181] = 0x21DC;
  gp_map[182] = 0x21DE;
  gp_map[183] = 0x21C0;
  gp_map[184] = 0x21C2;
  gp_map[185] = 0x21C4;
  gp_map[186] = 0x21E2;
  gp_map[188] = 0x21B2;
  gp_map[189] = 0x21B4;
  gp_map[190] = 0x21B6;
  gp_map[191] = 0x21B8;
  for (i = 0; i < MAX_GPIO; i++)
  {
    gp_map[i] -= (OMAP34XX_PADCONF_START - 0x48000000);
    alt_map[i] -= (OMAP34XX_PADCONF_START - 0x48000000);
  }
}

module_init(cmpc_init);
module_exit(cmpc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank Agius - iRobot");
MODULE_DESCRIPTION("Set the PADCONF register on the OMAP3");


