```
(cd /sys/bus/iio/devices/iio:device0/scan_elements/ && for file in *_en; do echo 1 > $file; done)
echo 500 > /sys/bus/iio/devices/iio:device0/sampling_frequency
strace iio_readdev -b 256 -a -s 0 icm20608 &> /dev/null &
```

# local board

```
# iiod
```

# remote host

```
# ./iio_info -n [host_address]
# iio_attr -u ip:[host_address] -d
# ./iio_readdev -u ip:[host_address] -b 256 -s 0 icm20608
```
