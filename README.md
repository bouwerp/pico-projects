```
mkdir build
cd build
PICO_BOARD=pico_w  PICO_SDK_PATH=../../pico-sdk cmake -DWIFI_SSID="SSID" -DWIFI_PASSWORD="PASSWORD" ..
make TARGET
```

