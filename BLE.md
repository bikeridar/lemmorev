## BLE
Most of the BLE communication seems to work by sending "packets" (XRequest/XRequest2) to a GATT service.

These support the following operations:
| Operation Code        | Description                        |
|-----------------------|------------------------------------|
| 1                     | PAIR                               |
| 5                     | FUN_SENDER_UNBIND                  |
| 39                    | FUN_SENDER_DPS2                    |

and the publishing of the following DPs (Tuya Data Points):
| DP Code | Data Point Description               |
|---------|---------------------------------------|
| 1       | lock                                  |
| 2       | speed                                 |
| 3       | smartpac_battery                      |
| 5       | totalTrip                             |
| 6       | totalRidingTime                       |
| 7       | averageSpeed                          |
| 8       | lights                                |
| 9       | smartpac_estimatedRange               |
| 11      | unitSet                               |
| 17      | smartpac_search                       |
| 29      | phoneKey                              |
| 32      | smartpac_batteryInfo                  |
| 38      | smartpac_gpsPosition                  |
| 41      | smartpac_gpsSignalStrength            |
| 42      | smartpac_cellularSignalStrength       |
| 43      | smartpac_iccid                        |
| 44      | smartpac_imei                         |
| 63      | smartpac_smartpacLock                 |
| 93      | autoLock                              |
| 96      | bluetoothParing                       |
| 101     | beep                                  |
| 103     | restart bike computer                 |
| 108     | boundSmartpacId                       |
| 109     | auto lock time                        |
| 120     | customString                          |
| 121     | smartpac_batteryExist                 |