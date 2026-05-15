open Core
open Procfs
module Unix = Core_unix

let test () =
  let caller_login = Unix.getlogin ()
  and caller_uid = Unix.getuid () in
  let process_list = get_all_procs () in
  let process_list =
    List.sort process_list ~compare:(fun a b ->
      Pid.compare (Process.pid a) (Process.pid b))
  in
  print_s [%message "process_list" (process_list : Process.t list)];
  let (_ : Process.t) = with_pid_exn (Pid.of_int 10) in
  let process_option = with_pid (Pid.of_int 10) in
  let (_ : Process.t list) = with_uid caller_uid in
  let (_ : Process.t list option) = with_username caller_login in
  let uptime = uptime () in
  print_s [%message "uptime" (uptime : Time_ns.Span.t)];
  let jiffies_per_second = jiffies_per_second () in
  print_s [%message "jiffies" (jiffies_per_second : float option)];
  let process = Option.value_exn process_option in
  let (_ : Time_ns.Span.t option) = process_age process in
  let meminfo = meminfo () in
  print_s [%message "meminfo" (meminfo : Meminfo.t option)];
  let loadavg = loadavg () in
  print_s [%message "loadavg" (loadavg : Loadavg.t option)];
  let pgrep = pgrep (fun p -> Process.pid p |> Pid.to_int = 10) in
  print_s [%message "pgrep result" (pgrep : Process.t list)];
  let pkill_result =
    pkill ~signal:Signal.kill (fun p ->
      Option.compare String.compare (Process.exe p) (Some "/usr/bin/yes") = 0)
  in
  print_s
    [%message
      "pkill result" (pkill_result : (Pid.t * (unit, Unix.Error.t) Result.t) list)]
;;

open Command.Let_syntax

let process_command =
  Command.basic
    ~summary:"show / start / kill some processes"
    [%map_open
      let () = return () in
      fun () ->
        let () = raise_s [%message "read my code before you run me"] in
        for _ = 1 to 10 do
          test ()
        done]
;;

let ps_command =
  Command.basic
    ~summary:"show all running processes"
    [%map_open
      let () = return () in
      fun () ->
        let process_list = get_all_procs () in
        List.iter process_list ~f:(fun p -> print_s [%sexp (p : Process.t)])]
;;

module type Net_l4proto = sig
  type t [@@deriving sexp_of]

  val load_exn : unit -> t list
end

let proc_net_l4proto filename m =
  let module M = (val m : Net_l4proto) in
  printf "- parsing %s\n" filename;
  M.load_exn () |> printf !"%{sexp:M.t list}\n"
;;

let proc_net_l4proto_command =
  Command.basic
    ~summary:"parse /proc/net/arp and /proc/net/{tcp,udp,raw,igmp}{,6}"
    [%map_open
      let () = return () in
      fun () ->
        List.iter
          [ "/proc/net/arp", (module Net.Arp : Net_l4proto)
          ; "/proc/net/tcp", (module Net.Tcp : Net_l4proto)
          ; "/proc/net/udp", (module Net.Udp : Net_l4proto)
          ; "/proc/net/raw", (module Net.Raw : Net_l4proto)
          ; "/proc/net/igmp", (module Net.Igmp : Net_l4proto)
          ; "/proc/net/tcp6", (module Net.Tcp6 : Net_l4proto)
          ; "/proc/net/udp6", (module Net.Udp6 : Net_l4proto)
          ; "/proc/net/raw6", (module Net.Raw6 : Net_l4proto)
          ; "/proc/net/igmp6", (module Net.Igmp6 : Net_l4proto)
          ]
          ~f:(fun (filename, m) -> proc_net_l4proto filename m)]
;;

let command =
  Command.group
    ~summary:"run the procfs parsers on some stuff"
    [ "processes", process_command
    ; "proc-net-l4proto", proc_net_l4proto_command
    ; "ps", ps_command
    ]
;;

let () = Command_unix.run command
