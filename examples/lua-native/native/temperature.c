#include "temperature.h"

/* An ordinary shared C library, independent of Lua. */
double temperature_fahrenheit(double celsius) {
    return celsius * 9.0 / 5.0 + 32.0;
}
