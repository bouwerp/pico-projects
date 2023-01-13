/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <math.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "pico/cyw43_arch.h"
#include "hardware/flash.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#define SEND_DATA_INTERVAL 5000

#define TEST_TCP_SERVER_IP "192.168.68.108"
#define TCP_PORT 9999
#define DEBUG_printf printf
#define BUF_SIZE 4096
#define POLL_TIME_S 5
#define TEST_ITERATIONS 10

typedef struct TCP_CLIENT_T_ {
    struct tcp_pcb *tcp_pcb;
    ip_addr_t remote_addr;
    uint8_t buffer[BUF_SIZE];
    int buffer_len;
    int sent_len;
    bool complete;
    int run_count;
    bool connected;
} TCP_CLIENT_T;

static err_t tcp_client_close(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    err_t err = ERR_OK;
    if (state->tcp_pcb != NULL) {
        tcp_arg(state->tcp_pcb, NULL);
        tcp_poll(state->tcp_pcb, NULL, 0);
        tcp_sent(state->tcp_pcb, NULL);
        tcp_recv(state->tcp_pcb, NULL);
        tcp_err(state->tcp_pcb, NULL);
        err = tcp_close(state->tcp_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(state->tcp_pcb);
            err = ERR_ABRT;
        }
        state->tcp_pcb = NULL;
    }
    return err;
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("tcp_client_sent %u\n", len);
    state->complete = true;
    return ERR_OK;
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (err != ERR_OK) {
        printf("connect failed %d\n", err);
        return ERR_ABRT;
    }
    state->connected = true;

    printf("[*] connected to server %d\n", err);

    return ERR_OK;
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_client_poll\n");
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    state->complete = false;
    return ERR_OK;
}

static void tcp_client_err(void *arg, err_t err) {
    if (err != ERR_OK ) {
        DEBUG_printf("tcp_client_err %d\n", err);
    }
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    switch (err) {
    case ERR_ABRT:
    case ERR_CONN:
    case ERR_RST:
    case ERR_CLSD:
        state->connected = false;
        break;
    default:
        break;
    }
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    return ERR_OK;
}

static bool tcp_client_open(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("Connecting to %s port %u\n", ip4addr_ntoa(&state->remote_addr), TCP_PORT);
    state->tcp_pcb = tcp_new_ip_type(IP_GET_TYPE(&state->remote_addr));
    if (!state->tcp_pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    tcp_arg(state->tcp_pcb, state);
    // tcp_poll(state->tcp_pcb, tcp_client_poll, POLL_TIME_S * 2);
    tcp_sent(state->tcp_pcb, tcp_client_sent);
    tcp_recv(state->tcp_pcb, tcp_client_recv);
    tcp_err(state->tcp_pcb, tcp_client_err);

    state->buffer_len = 0;

    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();
    err_t err = tcp_connect(state->tcp_pcb, &state->remote_addr, TCP_PORT, tcp_client_connected);
    cyw43_arch_lwip_end();

    return err == ERR_OK;
}

static TCP_CLIENT_T* tcp_client_init(void) {
    TCP_CLIENT_T *state = calloc(1, sizeof(TCP_CLIENT_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    ip4addr_aton(TEST_TCP_SERVER_IP, &state->remote_addr);
    return state;
}

int main() {
    stdio_init_all();

    adc_init();

    // Make sure GPIO is high-impedance, no pullups etc
    adc_gpio_init(28);
    // Select ADC input 2 (GPIO28)
    adc_select_input(2);


    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }

    cyw43_arch_enable_sta_mode();

    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 10000)) {
        printf("failed to connect\n");
        return 1;
    }

    TCP_CLIENT_T *state = tcp_client_init();
    if (!state) {
        DEBUG_printf("init failed - returning\n");
        exit(-1);
    }
    int status = tcp_client_open(state);
    if (!status) {
        DEBUG_printf("failed to connect to server\n");
        exit(-1);
    } 

    float y = 0, y_prev = 0, x = 0, x_prev = 0, y_r = 0, y_r_prev = 0, z = 0, z_prev = 0;
    float avg_total = 0, z_avg = 0, i_avg, p_avg = 0;
    int counter = 0;
    bool first_value = true;
    while (true) {
        const float conversion_factor = 3.3f / (1 << 12);
        uint16_t result = adc_read();

        x = 1000*(result * conversion_factor);

        // DC filter
        y = x - x_prev + 0.995 * y_prev;
        x_prev = x;
        y_prev = y;


        // Rectify
        y_r = abs(y);

        // Filter
        z = 0.9*z_prev + 0.1*y_r;
        y_r_prev = y_r;
        z_prev = z;

        avg_total += z;

        if (++counter == SEND_DATA_INTERVAL) {
            if (first_value) {
                // stops huge first value on startup
                first_value = false;
                avg_total = 0;
            }
            // average
            z_avg = avg_total / SEND_DATA_INTERVAL;
            i_avg = (100*(z_avg / 1000))/sqrt(2);
            p_avg = 230*i_avg;

            counter = 0;
            avg_total = 0;

            if (!state->connected) {
                DEBUG_printf("[!!!] connecting to server...\n");
                int status = tcp_client_open(state);
                if (!status) {
                    DEBUG_printf("failed to connect to server\n");
                    continue;
                } 
            }

            int buffer_size;
            if (p_avg < 10) {
                buffer_size = 4;
            } else if (p_avg >= 10 && p_avg < 100) {
                buffer_size = 5;
            } else if (p_avg >= 100 && p_avg < 1000) {
                buffer_size = 6;
            } else if (p_avg >= 1000 && p_avg < 10000) {
                buffer_size = 7;
            } else if (p_avg >= 10000 && p_avg < 100000) {
                buffer_size = 8;
            } else {
                DEBUG_printf("value out of bounds\n");
                continue;
            }

            char *power = (char*)malloc(buffer_size*sizeof(char));
            sprintf(power, "%.2f", p_avg);

            err_t err;
            if ((err = tcp_write(state->tcp_pcb, power, buffer_size, TCP_WRITE_FLAG_COPY)) != ERR_OK) {
                DEBUG_printf("failed to write data %d\n", err);
            }
            if ((err = tcp_output(state->tcp_pcb)) != ERR_OK) {
                DEBUG_printf("failed to flush data %d\n", err);
            }
            free(power);
        }
            
        sleep_us(1000);
    }
    
    cyw43_arch_deinit();
    tcp_client_close(state);
    return 0;
}

