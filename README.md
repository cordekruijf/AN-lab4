# AN lab 4 - P4 part 1
Ternary match of multicast/broadcast [MAC address](https://opennetworking.org/wp-content/uploads/2020/12/P4_tutorial_01_basics.gslide.pdf).
```
table_add m_table m_action 01:00:00:00:00:00&&&01:00:00:00:00:00 => 1 0
```