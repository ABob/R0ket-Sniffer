// Keyboard Sniffer

#ifndef __RADI1_H__
#define __RADI1_H__

#include "basic/basic.h"
#include "core/gpio/gpio.h"
#include "funk/nrf24l01p.h"


enum high_low
{
    LOW = 0,
    HIGH = 1
};


typedef struct
{
    int addr[5];
    int count;
} addr_count;


// Defined as a macro in "funk/nrf24l01p.c" but missing from header file
inline void
nrf_set_ce(enum high_low value)
{
    gpioSetValue(RB_NRF_CE, (uint8_t) value);
}


// Defined as a macro in "funk/nrf24l01p.c" but missing from header file
inline void
nrf_read_reg_long(uint8_t reg, int len, uint8_t* data)
{
    nrf_write_long(C_R_REGISTER | (reg & 0x1f), len, data);
}


// Defined as a macro in "funk/nrf24l01p.c" but missing from header file
inline void
nrf_write_reg_long(uint8_t reg, int len, const uint8_t* data)
{
    nrf_write_long(C_W_REGISTER | (reg & 0x1f), len, data);
}


// Defined in "funk/nrf24l01p.c" but not declared in header file
void nrf_read_pkt(int len, uint8_t* data);


// Valid values for register DYNPL, not defined in header file
#define R_DYNPD_DPL_P5 0x20
#define R_DYNPD_DPL_P4 0x10
#define R_DYNPD_DPL_P3 0x08
#define R_DYNPD_DPL_P2 0x04
#define R_DYNPD_DPL_P1 0x02
#define R_DYNPD_DPL_P0 0x01


// Register FEATURE, not defined in header file
#define R_FEATURE 0x1d

// Valid values for register FEATURE, not defined in header file
#define R_FEATURE_EN_DPL 0x04
#define R_FEATURE_EN_ACK_PAY 0x02
#define R_FEATURE_EN_DYN_ACK 0x01

#endif /* __RADI1_H__ */