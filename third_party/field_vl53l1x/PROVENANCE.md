# VL53L1X IDF driver

MOVEI144/KG `1e91d02202ad25c43f21a0274c000f9f5ee1000a`,
`firmware/display/components/vl53l1x/{VL53L1X.h,VL53L1X.cpp,LICENSE.txt}`.
BSD-3-Clause, STMicroelectronics 2017 and Pololu 2018–2022; notices retained.
The driver retains Pololu/ST initialization, timing calculations, manual
calibration, DSS, gain correction and mapped statuses, with KG's native IDF
transactions and sticky I/O error handling. Only `display-tof` links it.

Local changes: header attribution comment; C++ source layout/comments shortened,
with the original initialization, ranging, calibration and status algorithms retained.
No Arduino transport or simplified
register-only replacement. Acquisition calls `dataReady()` then `read(false)`.
