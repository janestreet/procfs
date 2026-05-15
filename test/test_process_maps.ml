open! Core

let%expect_test "Procfs.Process.Maps parses sample file" =
  [ "00400000-00860000 r-xp 00000000 00:40 11731874349 /home/user/.cargo/bin/bat"
  ; "00a5f000-00a8b000 r--p 0045f000 00:40 11731874349 /home/user/.cargo/bin/bat"
  ; "00a8b000-00a94000 rw-p 0048b000 00:40 11731874349 /home/user/.cargo/bin/bat"
  ; "01777000-01808000 rw-p 00000000 00:00 0                                  [heap]"
  ; "7f8397438000-7f83975fc000 r-xp 00000000 fd:00 1932 /usr/lib64/libc-2.17.so"
  ; "7f83975fc000-7f83977fb000 ---p 001c4000 fd:00 1932 /usr/lib64/libc-2.17.so"
  ; "7f83977fb000-7f83977ff000 r--p 001c3000 fd:00 1932 /usr/lib64/libc-2.17.so"
  ; "7f83977ff000-7f8397801000 rw-p 001c7000 fd:00 1932 /usr/lib64/libc-2.17.so"
  ; "7fffe8cec000-7fffeecec000 r--s 00000000 00:14 59473 /path with spaces"
  ; "7f8397801000-7f8397806000 rw-p 00000000 00:00 0 "
  ; "7f8397806000-7f8397808000 r-xp 00000000 fd:00 1938  "
  ; "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]"
  ]
  |> Procfs.Process.Maps.of_lines
  |> Procfs.Process.Maps.sexp_of_t
  |> print_s;
  [%expect
    {|
    (((start_addr 0x400000) (end_addr 0x860000)
      (permissions (read execute private)) (label (/home/user/.cargo/bin/bat))
      (offset 0x0))
     ((start_addr 0xa5f000) (end_addr 0xa8b000) (permissions (read private))
      (label (/home/user/.cargo/bin/bat)) (offset 0x45f000))
     ((start_addr 0xa8b000) (end_addr 0xa94000)
      (permissions (read write private)) (label (/home/user/.cargo/bin/bat))
      (offset 0x48b000))
     ((start_addr 0x1777000) (end_addr 0x1808000)
      (permissions (read write private)) (label ([heap])) (offset 0x0))
     ((start_addr 0x7f8397438000) (end_addr 0x7f83975fc000)
      (permissions (read execute private)) (label (/usr/lib64/libc-2.17.so))
      (offset 0x0))
     ((start_addr 0x7f83975fc000) (end_addr 0x7f83977fb000)
      (permissions (private)) (label (/usr/lib64/libc-2.17.so))
      (offset 0x1c4000))
     ((start_addr 0x7f83977fb000) (end_addr 0x7f83977ff000)
      (permissions (read private)) (label (/usr/lib64/libc-2.17.so))
      (offset 0x1c3000))
     ((start_addr 0x7f83977ff000) (end_addr 0x7f8397801000)
      (permissions (read write private)) (label (/usr/lib64/libc-2.17.so))
      (offset 0x1c7000))
     ((start_addr 0x7fffe8cec000) (end_addr 0x7fffeecec000) (permissions (read))
      (label ("/path with spaces")) (offset 0x0))
     ((start_addr 0x7f8397801000) (end_addr 0x7f8397806000)
      (permissions (read write private)) (label ()) (offset 0x0))
     ((start_addr 0x7f8397806000) (end_addr 0x7f8397808000)
      (permissions (read execute private)) (label ()) (offset 0x0))
     ((start_addr -0xa00000) (end_addr -0x9ff000)
      (permissions (read execute private)) (label ([vsyscall])) (offset 0x0)))
    |}]
;;
