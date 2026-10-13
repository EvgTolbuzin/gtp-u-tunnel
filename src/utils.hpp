#pragma once

#include <cstdint>
#include "structures.hpp"

// Поиск UE по IP или по TEID uplink. Возвращает nullptr, если не найден.
const Ue* findUeByIp(uint32_t ip);
const Ue* findUeByTeidUl(uint32_t teid_ul);

// Получить MAC интерфейса через ioctl.
bool getMacAddress(const char* ifname, uint8_t mac[MAC_LEN]);

// Напечатать MAC в формате aa:bb:cc:dd:ee:ff.
void printMac(const char* prefix, const uint8_t mac[MAC_LEN]);