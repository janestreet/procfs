open Core
open File_path.Operators
module Unix = Core_unix

let%expect_test "Procfs.get_locks parses sample /proc/locks content" =
  let content =
    {|
1: POSIX  ADVISORY  READ 5433 08:01:7864448 128 128
2: FLOCK  ADVISORY  WRITE 2001 08:01:7864554 0 EOF
3: FLOCK  ADVISORY  WRITE 1568 00:2f:32388 0 EOF
4: -> FLOCK  ADVISORY  WRITE 807744 00:6f:793922 0 EOF
5: POSIX  ADVISORY  WRITE 699 00:16:28457 0 EOF
6: POSIX  ADVISORY  WRITE 764 00:16:21448 0 0
7: POSIX  ADVISORY  READ 3548 08:01:7867240 1 1
8: POSIX  ADVISORY  READ 3548 08:01:7865567 1826 2335
9: OFDLCK ADVISORY  WRITE -1 08:01:8713209 128 191
46: POSIX  ADVISORY  WRITE 163033 00:10e:11 0 EOF
|}
    |> String.lstrip
  in
  content
  |> String.split_lines
  |> Procfs.For_testing.parse_locks
  |> [%sexp_of: Procfs.Lock.t list]
  |> print_s;
  [%expect
    {|
    (((mechanism (Posix (5433) ((start 128) (end_ (At 128))))) (type_ Read)
      (inode ((((major 8) (minor 1)) 7864448))))
     ((mechanism (Flock (2001))) (type_ Write)
      (inode ((((major 8) (minor 1)) 7864554))))
     ((mechanism (Flock (1568))) (type_ Write)
      (inode ((((major 0) (minor 47)) 32388))))
     ((mechanism (Posix (699) ((start 0) (end_ Eof)))) (type_ Write)
      (inode ((((major 0) (minor 22)) 28457))))
     ((mechanism (Posix (764) ((start 0) (end_ (At 0))))) (type_ Write)
      (inode ((((major 0) (minor 22)) 21448))))
     ((mechanism (Posix (3548) ((start 1) (end_ (At 1))))) (type_ Read)
      (inode ((((major 8) (minor 1)) 7867240))))
     ((mechanism (Posix (3548) ((start 1826) (end_ (At 2335))))) (type_ Read)
      (inode ((((major 8) (minor 1)) 7865567))))
     ((mechanism (Ofd ((start 128) (end_ (At 191))))) (type_ Write)
      (inode ((((major 8) (minor 1)) 8713209))))
     ((mechanism (Posix (163033) ((start 0) (end_ Eof)))) (type_ Write)
      (inode ((((major 0) (minor 270)) 11)))))
    |}]
;;

let%test_unit "[get_pids_holding_flock]" =
  Filesystem_core.within_temp_dir (fun () ->
    let lockfile = ?/"lockfile" in
    (* Test exclusive lock. *)
    let flock = Filesystem_core.flock_create lockfile in
    let pids = Procfs.get_pids_holding_flock lockfile in
    assert ([%equal: Pid.t list] pids [ Unix.getpid () ]);
    (* Test unlocked. *)
    Filesystem_core.funlock flock;
    assert (List.is_empty (Procfs.get_pids_holding_flock lockfile));
    (* Test shared lock. *)
    let parent_sock, child_sock =
      Unix.socketpair ~domain:PF_UNIX ~kind:SOCK_DGRAM ~protocol:0 ()
    in
    let send fd msg =
      let bytes_sent =
        Unix.send_substring fd ~buf:msg ~pos:0 ~len:(String.length msg) ~mode:[]
      in
      assert (bytes_sent = String.length msg)
    in
    let await fd msg =
      let buf = Bytes.create (String.length msg) in
      let bytes_received = Unix.recv fd ~buf ~pos:0 ~len:(String.length msg) ~mode:[] in
      assert (bytes_received = String.length msg);
      assert (String.equal (Bytes.to_string buf) msg)
    in
    match Unix.fork () with
    | `In_the_parent child_pid ->
      Unix.close child_sock;
      let (_ : Filesystem_core.Flock.t) = Filesystem_core.flock ~shared:true lockfile in
      await parent_sock "locked";
      let pids = Procfs.get_pids_holding_flock lockfile |> Pid.Set.of_list in
      send parent_sock "exit";
      Unix.close parent_sock;
      let child_exit_status = Unix.waitpid child_pid in
      assert (Result.is_ok child_exit_status);
      let expected_pids = Pid.Set.of_list [ Unix.getpid (); child_pid ] in
      assert ([%equal: Pid.Set.t] pids expected_pids)
    | `In_the_child ->
      Unix.close parent_sock;
      let (_ : Filesystem_core.Flock.t) = Filesystem_core.flock ~shared:true lockfile in
      send child_sock "locked";
      await child_sock "exit")
;;
