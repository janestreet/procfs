module Stable = struct
  open Core.Core_stable

  module Net = struct
    module Ipproto = struct
      module V1 = struct
        type t =
          | ICMP
          | IGMP
          | IPIP
          | TCP
          | EGP
          | PUP
          | UDP
          | IDP
          | TP
          | DCCP
          | IPV6
          | RSVP
          | GRE
          | ESP
          | AH
          | MTP
          | BEETPH
          | ENCAP
          | PIM
          | COMP
          | SCTP
          | UDPLITE
          | RAW
          | Unknown of int
        [@@deriving bin_io, compare ~localize, sexp]
      end
    end
  end

  module Diskstat = struct
    module V1 = struct
      type t =
        { major : int
        ; minor : int
        ; device_name : string
        ; reads : int64
        ; reads_merged : int64
        ; sectors_read : int64
        ; read_time : int
        ; writes : int64
        ; writes_merged : int64
        ; sectors_written : int64
        ; write_time : int
        ; io_in_progress : int
        ; io_time : int
        ; weighted_io_time : int
        ; discards : int64 option
        ; discards_merged : int64 option
        ; sectors_discarded : int64 option
        ; discard_time : int option
        ; flushes : int64 option
        ; flush_time : int option
        }
      [@@deriving bin_io, compare ~localize, sexp]
    end
  end
end

open Core
open Float.Robustly_comparable
module Unix = Core_unix

(* so that procfs async can refer to Procfs_intf *)
module Procfs_intf = Procfs_intf

(* The functions here are shared by blocking and async *)
module Make (IO : Procfs_intf.IO) = struct
  open IO.Monad.Let_syntax
  open IO.Monad.Monad_infix

  type file_descr = IO.file_descr

  (* Learn more about this business by consulting proc(5) *)

  (* lu and ld match the proc(5) format strings %lu and %ld *)
  let lu x = Big_int.big_int_of_string x
  let ld x = lu x
  let lu' x = Int64.of_string x

  (* bigint everything so we don't have to worry about overflows *)

  type bigint = Big_int.big_int

  let sexp_of_bigint x = Sexp.Atom (Big_int.string_of_big_int x)

  let get_uptime () =
    match%map IO.string_of_file "/proc/uptime" >>| String.split ~on:' ' with
    | secs_since_boot :: _ -> Float.of_string secs_since_boot
    | _ -> failwithf "Error parsing /proc/uptime" ()
  ;;

  let process_age ~start_time ~jiffies_per_second =
    let start_time = Big_int.float_of_big_int start_time /. jiffies_per_second in
    let%map uptime = get_uptime () in
    Time_ns.Span.of_sec (uptime -. start_time)
  ;;

  module Process = struct
    module Inode : sig
      type t [@@deriving sexp_of]

      val of_string : string -> t
      val to_string : t -> string
      val of_int64 : int64 -> t
      val to_int64 : t -> int64
      val of_int : int -> t

      include%template Comparable.S_plain [@mode local] with type t := t

      include Hashable.S_plain with type t := t
    end =
      Int64

    module Limits = struct
      module Rlimit = struct
        type value =
          [ `unlimited
          | `limited of bigint
          ]
        [@@deriving sexp_of]

        type t =
          { soft : value
          ; hard : value
          }
        [@@deriving fields ~getters, sexp_of]
      end

      type t =
        { cpu_time : Rlimit.t
        ; file_size : Rlimit.t
        ; data_size : Rlimit.t
        ; stack_size : Rlimit.t
        ; core_file_size : Rlimit.t
        ; resident_set : Rlimit.t
        ; processes : Rlimit.t
        ; open_files : Rlimit.t
        ; locked_memory : Rlimit.t
        ; address_space : Rlimit.t
        ; file_locks : Rlimit.t
        ; pending_signals : Rlimit.t
        ; msgqueue_size : Rlimit.t
        ; nice_priority : Rlimit.t
        ; realtime_priority : Rlimit.t
        }
      [@@deriving fields ~getters, sexp_of]

      let of_string s =
        let map =
          String.split s ~on:'\n'
          |> List.map ~f:String.strip
          |> List.filter ~f:(Fn.non String.is_empty)
          |> List.fold ~init:String.Map.empty ~f:(fun map line ->
            match
              String.strip line
              |> String.lowercase
              |> String.split ~on:' '
              |> List.filter ~f:(Fn.non String.is_empty)
              |> List.rev
            with
            | ("units" | "seconds" | "bytes" | "processes" | "locks" | "signals" | "files")
              :: hard_limit
              :: soft_limit
              :: name ->
              let key = List.rev name |> String.concat ~sep:" " in
              Map.set map ~key ~data:(soft_limit, hard_limit)
            (* priorities don't have an entry in the "Units" column *)
            | hard_limit :: soft_limit :: name ->
              let key = List.rev name |> String.concat ~sep:" " in
              Map.set map ~key ~data:(soft_limit, hard_limit)
            | _ -> failwithf "Procfs.Limits.of_string bad format: %s" line ())
        in
        let get key =
          let data =
            match Map.find map key with
            | Some data -> data
            | None -> failwithf "Procfs.Limits.of_string: bad key %s" key ()
          in
          let value x =
            if String.equal x "unlimited"
            then `unlimited
            else `limited (Big_int.big_int_of_string x)
          in
          { Rlimit.soft = fst data |> value; hard = snd data |> value }
        in
        { cpu_time = get "max cpu time"
        ; file_size = get "max file size"
        ; data_size = get "max data size"
        ; stack_size = get "max stack size"
        ; core_file_size = get "max core file size"
        ; resident_set = get "max resident set"
        ; processes = get "max processes"
        ; open_files = get "max open files"
        ; locked_memory = get "max locked memory"
        ; address_space = get "max address space"
        ; file_locks = get "max file locks"
        ; pending_signals = get "max pending signals"
        ; msgqueue_size = get "max msgqueue size"
        ; nice_priority = get "max nice priority"
        ; realtime_priority = get "max realtime priority"
        }
      ;;

      let of_string_opt s = Option.try_with (fun () -> of_string s)
    end

    module Maps = struct
      module Permissions = struct
        let bit n = Int63.of_int (1 lsl n)
        let read = bit 3
        let write = bit 2
        let execute = bit 1
        let private_ = bit 0

        include Flags.Make (struct
            let allow_intersecting = false
            let should_print_error = true
            let remove_zero_flags = false

            let known =
              [ read, "read"; write, "write"; execute, "execute"; private_, "private" ]
            ;;
          end)

        let[@cold] raise_invalid_perm_string str =
          raise_s [%message "invalid perm string" (str : string)]
        ;;

        let of_string str =
          if Int.(String.length str > 4) then raise_invalid_perm_string str;
          let set_if ?(isn't = '-') ~pos ~is bit flags =
            let c = String.get str pos in
            if Char.(c = is)
            then flags + bit
            else if Char.(c = isn't)
            then flags
            else raise_invalid_perm_string str
          in
          empty
          |> set_if private_ ~pos:3 ~is:'p' ~isn't:'s'
          |> set_if execute ~pos:2 ~is:'x'
          |> set_if write ~pos:1 ~is:'w'
          |> set_if read ~pos:0 ~is:'r'
        ;;
      end

      module Entry = struct
        type t =
          { start_addr : Int64.Hex.t
          ; end_addr : Int64.Hex.t
          ; permissions : Permissions.t
          ; label : string option
          ; offset : Int64.Hex.t
          }
        [@@deriving sexp_of]

        let[@cold] raise_invalid_map_string str =
          raise_s [%message "invalid proc maps entry" (str : string)]
        ;;

        let of_string str =
          let make ?label ~start_addr ~end_addr ~permissions ~offset () =
            let permissions = Permissions.of_string permissions in
            { start_addr; end_addr; offset; permissions; label }
          in
          try
            Scanf.sscanf
              str
              "%LX-%LX %s %LX %s %s%s@$"
              (fun start_addr end_addr permissions offset _dev _inode label ->
                 let label = String.lstrip label in
                 if String.is_empty label
                 then make ~start_addr ~end_addr ~permissions ~offset ()
                 else make ~start_addr ~end_addr ~permissions ~label ~offset ())
          with
          | _exn -> raise_invalid_map_string str
        ;;
      end

      type t = Entry.t list [@@deriving sexp_of]

      let of_lines = List.map ~f:Entry.of_string
      let of_string s = String.split_lines s |> of_lines
    end

    module Stat = struct
      module State = struct
        type t =
          | Running
          | Interruptible_sleep
          | Uninterruptible_disk_sleep
          | Zombie
          | Stopped
          | Tracing_stop
          | Dead
          | Unknown of char
        [@@deriving equal ~localize, sexp_of]
      end

      type t =
        { comm : string (** The filename of the executable *)
        ; state : State.t (** One character from the string "RSDZTW" *)
        ; ppid : Pid.t option (** The PID of the parent. *)
        ; pgrp : Pid.t option (** The process group ID of the process. *)
        ; session : int (** The session ID of the process. *)
        ; tty_nr : int (** The tty the process uses. *)
        ; tpgid : int
        (** The process group ID of the process which currently owns the tty... *)
        ; flags : bigint (** The kernel flags word of the process. *)
        ; minflt : bigint
        (** The number of minor faults the process has made which have not required
            loading a memory page from disk. *)
        ; cminflt : bigint
        (** The number of minor faults that the process’s waited-for children have made. *)
        ; majflt : bigint
        (** The number of major faults the process has made which have required loading a
            page from disk. *)
        ; cmajflt : bigint
        (** The number of major faults that the process’s waited-for children have made. *)
        ; utime : bigint
        (** The number of jiffies that this process has been scheduled in user mode. *)
        ; stime : bigint
        (** The number of jiffies that this process has been scheduled in kernel mode. *)
        ; cutime : bigint
        (** The number of jiffies that this process’s waited-for children have been
            scheduled in user mode. *)
        ; cstime : bigint
        (** The number of jiffies that this process’s waited-for children have been
            scheduled in kernel mode. *)
        ; priority : bigint
        (** The standard nice value, plus fifteen. The value is never negative in the
            kernel. *)
        ; nice : bigint (** The nice value ranges from 19 to -19 *)
        ; num_threads : bigint
        (** Number of threads in this process (since Linux 2.6). Before Linux 2.6, this
            field was hard coded to 0 as a placeholder for an earlier removed field. *)
        ; itrealvalue : bigint
        (** The time in jiffies before the next SIGALRM is sent to the process due to an
            interval timer. *)
        ; starttime : bigint
        (** The time in jiffies the process started after system boot. *)
        ; vsize : bigint (** Virtual memory size in bytes. *)
        ; rss : bigint
        (** Resident Set Size: number of pages the process has in real memory. *)
        ; rlim : bigint (** Current limit in bytes on the rss of the process. *)
        ; startcode : bigint (** The address above which program text can run. *)
        ; endcode : bigint (** The address below which program text can run. *)
        ; startstack : bigint (** The address of the start of the stack. *)
        ; kstkesp : bigint (** The current value of esp (stack pointer) *)
        ; kstkeip : bigint (** The current value of eip (instruction pointer) *)
        ; signal : bigint
        (** The bitmap of pending signals. Obsolete, because it does not provide
            information on real-time signals; use /proc/pid/status instead. *)
        ; blocked : bigint
        (** The bitmap of blocked signals. Obsolete, because it does not provide
            information on real-time signals; use /proc/pid/status instead. *)
        ; sigignore : bigint
        (** The bitmap of ignored signals. Obsolete, because it does not provide
            information on real-time signals; use /proc/pid/status instead. *)
        ; sigcatch : bigint (** The bitmap of caught signals. *)
        ; wchan : bigint
        (** This is the "channel" in which the process is waiting. Address of a system
            call. *)
        ; nswap : bigint (** (no longer maintained) *)
        ; cnswap : bigint (** (no longer maintained) *)
        ; exit_signal : int (** Signal sent to parent when we die. *)
        ; processor : int (** CPU number last executed on. *)
        ; rt_priority : bigint (** Real-time scheduling priority. *)
        ; policy : bigint (** Scheduling policy *)
        ; delayacct_blkio_ticks : bigint
        (** Aggregated block I/O delays, measured in clock ticks (centiseconds). *)
        ; guest_time : bigint
        (** Guest time of the process (time spent running a virtual CPU for a guest
            operating system), measured in clock ticks (divide by ticks_per_second()) *)
        ; cguest_time : bigint
        (** Guest time of the process’s children, measured in clock ticks (divide by
            ticks_per_second()). *)
        ; start_data : int64
        (** Address above which program initialized and uninitialized (BSS) data are
            placed. *)
        ; end_data : int64
        (** Address below which program initialized and uninitialized (BSS) data are
            placed. *)
        ; start_brk : int64
        (** Address above which program heap can be expanded with brk(2). *)
        ; arg_start : int64
        (** Address above which program command-line arguments (argv) are placed. *)
        ; arg_end : int64
        (** Address below program command-line arguments (argv) are placed. *)
        ; env_start : int64 (** Address above which program environment is placed. *)
        ; env_end : int64 (** Address below which program environment is placed. *)
        ; exit_code : int
        (** The thread’s exit status in the form reported by waitpid(2). *)
        }
      [@@deriving fields ~getters, sexp_of]

      (* extract_command, for a stat string such as: "14574 (cat) R 10615 14574 10615
         34820 14574 4194304 164 0..." returns this tuple "cat", "R 10615 14574 10615..." *)
      let extract_command s =
        let i = String.index_exn s '(' in
        let j = String.rindex_exn s ')' in
        ( `command (String.sub s ~pos:(i + 1) ~len:(j - (i + 1)))
        , `rest (String.sub s ~pos:(j + 1) ~len:(String.length s - (j + 1))) )
      ;;

      let of_string s =
        let `command comm, `rest rest = extract_command s in
        let a = Array.of_list (String.split (String.strip rest) ~on:' ') in
        let d x = int_of_string x in
        let c x = x.[0] in
        { comm
        ; state =
            (match c a.(0) with
             | 'R' -> Running
             | 'S' -> Interruptible_sleep
             | 'D' -> Uninterruptible_disk_sleep
             | 'Z' -> Zombie
             | 'T' -> Stopped
             | 't' -> Tracing_stop
             | 'X' (* from Linux 2.6.0 onward *) | 'x' (* Linux 2.6.33 to 3.13 only *) ->
               Dead
             | c -> Unknown c)
        ; ppid =
            (match d a.(1) with
             | x when x < 1 -> None
             | x -> Some (Pid.of_int x))
        ; (*=pgrp        = Pid.of_int (d a.(2)); *)
          pgrp =
            (match d a.(2) with
             | x when x < 1 -> None
             | x -> Some (Pid.of_int x))
        ; session = d a.(3)
        ; tty_nr = d a.(4)
        ; tpgid = d a.(5)
        ; flags = ld a.(6)
        ; minflt = ld a.(7)
        ; cminflt = ld a.(8)
        ; majflt = ld a.(9)
        ; cmajflt = ld a.(10)
        ; utime = ld a.(11)
        ; stime = ld a.(12)
        ; cutime = ld a.(13)
        ; cstime = ld a.(14)
        ; priority = ld a.(15)
        ; nice = ld a.(16)
        ; num_threads = ld a.(17)
        ; itrealvalue = ld a.(18)
        ; starttime = lu a.(19)
        ; vsize = lu a.(20)
        ; rss = ld a.(21)
        ; rlim = lu a.(22)
        ; startcode = lu a.(23)
        ; endcode = lu a.(24)
        ; startstack = lu a.(25)
        ; kstkesp = lu a.(26)
        ; kstkeip = lu a.(27)
        ; signal = lu a.(28)
        ; blocked = lu a.(29)
        ; sigignore = lu a.(30)
        ; sigcatch = lu a.(31)
        ; wchan = lu a.(32)
        ; nswap = lu a.(33)
        ; cnswap = lu a.(34)
        ; exit_signal = d a.(35)
        ; processor = d a.(36)
        ; rt_priority = lu a.(37)
        ; policy = lu a.(38)
        ; delayacct_blkio_ticks = lu a.(39)
        ; guest_time = ld a.(40)
        ; cguest_time = lu a.(41)
        ; start_data = lu' a.(42)
        ; end_data = lu' a.(43)
        ; start_brk = lu' a.(44)
        ; arg_start = lu' a.(45)
        ; arg_end = lu' a.(46)
        ; env_start = lu' a.(47)
        ; env_end = lu' a.(48)
        ; exit_code = d a.(49)
        }
      ;;

      let load pid =
        IO.or_error_try_with (fun () ->
          IO.string_of_file [%string "/proc/%{pid#Pid}/stat"] >>| of_string)
      ;;

      let process_age t ~jiffies_per_second =
        process_age ~start_time:t.starttime ~jiffies_per_second
      ;;
    end

    module Statm = struct
      type t =
        { size : bigint (** total program size *)
        ; resident : bigint (** resident set size *)
        ; share : bigint (** shared pages *)
        ; text : bigint (** text (code) *)
        ; lib : bigint (** library *)
        ; data : bigint (** data/stack *)
        ; dt : bigint (** dirty pages (unused) *)
        }
      [@@deriving fields ~getters, sexp_of]

      let of_string s =
        let a = Array.of_list (String.split s ~on:' ') in
        { size = lu a.(0)
        ; resident = lu a.(1)
        ; share = lu a.(2)
        ; text = lu a.(3)
        ; lib = lu a.(4)
        ; data = lu a.(5)
        ; dt = lu a.(6)
        }
      ;;
    end

    module Status = struct
      type t =
        { uid : int (** Real user ID *)
        ; euid : int (** Effective user ID *)
        ; suid : int (** Saved user ID *)
        ; fsuid : int (** FS user ID *)
        ; gid : int (** Real group ID *)
        ; egid : int (** Effective group ID *)
        ; sgid : int (** Saved group ID *)
        ; fsgid : int (** FS group ID *)
        }
      [@@deriving fields ~getters, sexp_of]

      let of_string s =
        (* Splits "foo: 1\nbar: 2\n" into [Some ("foo"," 1"); Some ("bar"," 2"); None] *)
        let records =
          List.map (String.split s ~on:'\n') ~f:(fun x -> String.lsplit2 x ~on:':')
        in
        let _, uids =
          Option.value_exn
            (List.find_exn records ~f:(fun kv ->
               match kv with
               | Some ("Uid", _) -> true
               | _ -> false))
        in
        let _, gids =
          Option.value_exn
            (List.find_exn records ~f:(fun kv ->
               match kv with
               | Some ("Gid", _) -> true
               | _ -> false))
        in
        Scanf.sscanf
          (String.concat ~sep:" " [ String.strip uids; String.strip gids ])
          "%d %d %d %d %d %d %d %d"
          (fun a b c d e f g h ->
            { uid = a
            ; euid = b
            ; suid = c
            ; fsuid = d
            ; gid = e
            ; egid = f
            ; sgid = g
            ; fsgid = h
            })
      ;;
    end

    module Fd = struct
      module Onload = struct
        module Socket_id = struct
          type t =
            { stack : int
            ; socket : int
            }
          [@@deriving sexp_of]
        end

        type t =
          | Moved of Socket_id.t
          | Os_sock of Socket_id.t
          | Pipe_reader of Socket_id.t
          | Pipe_writer of Socket_id.t
          | Stack of int
          | Tcp of Socket_id.t
          | Tcp_listen of Socket_id.t
          | Udp of Socket_id.t
          | Unknown of string
        [@@deriving sexp_of]

        let parse_symlink data =
          match String.split data ~on:':' with
          | [ "moved"; stack; socket ] ->
            Moved { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "os_sock"; stack; socket ] ->
            Os_sock { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "piper"; stack; socket ] ->
            Pipe_reader { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "pipew"; stack; socket ] ->
            Pipe_writer { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "stack"; stack ] -> Stack (Int.of_string stack)
          | [ "tcp"; stack; socket ] ->
            Tcp { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "tcpl"; stack; socket ] ->
            Tcp_listen { stack = Int.of_string stack; socket = Int.of_string socket }
          | [ "udp"; stack; socket ] ->
            Udp { stack = Int.of_string stack; socket = Int.of_string socket }
          | _ -> Unknown data
        ;;
      end

      type fd_stat =
        | Path of string
        | Socket of Inode.t
        | Pipe of Inode.t
        | Inotify
        | Onload of Onload.t
      [@@deriving sexp_of]

      type t =
        { fd : int (** File descriptor (0=stdin, 1=stdout, etc.) *)
        ; fd_stat : fd_stat (** Kind of file *)
        }
      [@@deriving fields ~getters, sexp_of]

      let parse_symlink ~target =
        let strip_and parse s =
          s
          |> String.chop_prefix_exn ~prefix:"["
          |> String.chop_suffix_exn ~suffix:"]"
          |> parse
        in
        match String.lsplit2 ~on:':' target with
        | Some ("socket", inode) -> Socket (strip_and Inode.of_string inode)
        | Some ("pipe", inode) -> Pipe (strip_and Inode.of_string inode)
        | Some ("anon_inode", "inotify") -> Inotify
        | Some ("onload", data) -> Onload (strip_and Onload.parse_symlink data)
        | _ -> Path target
      ;;
    end

    module Cmdline = struct
      type t = string [@@deriving sexp_of]

      let to_raw_string t = t

      let parse s =
        match s with
        | "" -> None
        | s ->
          let s = String.chop_suffix_if_exists ~suffix:"\000" s in
          Some (String.split ~on:'\000' s)
      ;;

      let parse_or_empty s = Option.value ~default:[] (parse s)
      let to_shell_string t = Sys.concat_quoted (parse_or_empty t)
    end

    type t =
      { pid : Pid.t (** Process ID *)
      ; cmdline : string (** Command-line (not reliable). *)
      ; cwd : string option (** Symlink to working directory. *)
      ; environ : string list option (** Process environment. *)
      ; exe : string option (** Symlink to executed command. *)
      ; root : string option (** Per-process root (e.g. chroot) *)
      ; limits : Limits.t option (** Per-process rlimit settings *)
      ; maps : Maps.t option (** Per-process memory mappings *)
      ; stat : Stat.t (** Status information. *)
      ; statm : Statm.t (** Memory status information. *)
      ; status : Status.t (** Some more assorted status information. *)
      ; task_stats : Stat.t Pid.Map.t (** Status information for each task (thread) *)
      ; top_command : string (** Show what top would show for COMMAND *)
      ; fds : Fd.t list option (** File descriptors *)
      ; oom_adj : int
      ; oom_score : int
      }
    [@@deriving fields ~getters, sexp_of]

    let load ?(load_tasks = true) pid =
      let slurp f ~path conv =
        IO.or_error_try_with (fun () -> f [%string "/proc/%{pid#Pid}/%{path}"] >>| conv)
      and slurp_opt f ~path conv =
        IO.try_with_handler
          ~here:[%here]
          ~f:(fun () ->
            f [%string "/proc/%{pid#Pid}/%{path}"]
            >>| conv
            >>| Option.some
            >>| Or_error.return)
          ~handler:(function
            | Sys_error _ | Unix.Unix_error ((EACCES | EINVAL | ENOENT), _, _) -> Ok None
            | exn -> Or_error.of_exn exn)
      in
      let slurp_file ~path conv = slurp IO.string_of_file ~path conv
      and slurp_file_opt ~path conv = slurp_opt IO.string_of_file ~path conv
      and slurp_link_opt ~path = slurp_opt IO.readlink ~path Fn.id
      and slurp_dir ~path = slurp IO.readdir ~path Array.to_list
      and slurp_dir_opt ~path = slurp_opt IO.readdir ~path Array.to_list in
      let%bind cmdline = slurp_file ~path:"cmdline" Fn.id in
      (* Process command name varies

         cmdline is ideal but not guaranteed to be there because the kernel
         - may discard it in lomem situations
         - discard it for zombie processes
         - put nothing useful there for kernel processes

         The exe symlink might be useful, it's the name of the executable which started
         the process, but permission is usually denied for non-root/non-self viewers.

         The stat.command field will ALWAYS be there but is truncated to 16 chars; we do
         here what top does: use cmdline if it is populated, otherwise use stat.command.
      *)
      let%bind stat = slurp_file ~path:"stat" Stat.of_string in
      let%bind limits =
        slurp_file_opt ~path:"limits" Limits.of_string_opt >>| Or_error.map ~f:Option.join
      in
      let%bind maps = slurp_file_opt ~path:"maps" Maps.of_string in
      let%bind task_stats =
        if not load_tasks
        then Or_error.return Pid.Map.empty |> return
        else (
          match%bind slurp_dir ~path:"task" with
          | Error _ as error -> return error
          | Ok tasks ->
            IO.List.filter_map tasks ~f:(fun task ->
              match Or_error.try_with (fun () -> Pid.of_string task) with
              | Error _ as error -> return (Some error)
              | Ok pid ->
                (match%map
                   slurp_file_opt ~path:[%string "task/%{task}/stat"] Stat.of_string
                 with
                 | Error e -> Some (Error e)
                 | Ok (Some data) -> Some (Ok (pid, data))
                 | Ok None -> None))
            >>| Or_error.all
            >>| Or_error.map ~f:(Pid.Map.of_alist_reduce ~f:(fun _ data -> data)))
      in
      let%bind fds =
        match%bind slurp_dir_opt ~path:"fd" with
        | Error _ as error -> return error
        | Ok None -> return (Ok None)
        | Ok (Some fds) ->
          IO.List.map fds ~f:(fun fd_str ->
            match%map slurp_link_opt ~path:[%string "fd/%{fd_str}"] with
            | Error _ as error -> error
            | Ok None -> Ok None
            | Ok (Some target) ->
              Or_error.try_with (fun () ->
                let fd = Int.of_string fd_str
                and fd_stat = Fd.parse_symlink ~target in
                Some { Fd.fd; fd_stat }))
          >>| Or_error.all
          >>| Or_error.map ~f:(Fn.compose Option.some List.filter_opt)
      in
      let%bind cwd = slurp_link_opt ~path:"cwd" in
      let%bind environ =
        slurp_file_opt ~path:"environ" (function
          | "" -> []
          | s ->
            s |> String.chop_suffix_if_exists ~suffix:"\x00" |> String.split ~on:'\x00')
      in
      let%bind exe = slurp_link_opt ~path:"exe" in
      let%bind root = slurp_link_opt ~path:"root" in
      let%bind statm = slurp_file ~path:"statm" Statm.of_string in
      let%bind status = slurp_file ~path:"status" Status.of_string in
      let%bind oom_adj =
        slurp_file ~path:"oom_adj" (Fn.compose Int.of_string String.strip)
      in
      let%map oom_score =
        slurp_file ~path:"oom_score" (Fn.compose Int.of_string String.strip)
      in
      let open Or_error.Let_syntax in
      let%map cmdline
      and stat
      and limits
      and task_stats
      and fds
      and cwd
      and environ
      and exe
      and root
      and maps
      and statm
      and status
      and oom_adj
      and oom_score in
      let top_command =
        (if String.is_empty cmdline
         then Stat.comm stat
         else String.tr ~target:'\x00' ~replacement:' ' cmdline)
        |> String.strip
      in
      { pid
      ; cmdline
      ; cwd
      ; environ
      ; exe
      ; root
      ; limits
      ; maps
      ; stat
      ; statm
      ; status
      ; task_stats
      ; top_command
      ; fds
      ; oom_adj
      ; oom_score
      }
    ;;
  end

  module Meminfo = struct
    type t =
      { mem_total : bigint
      ; mem_free : bigint
      ; buffers : bigint
      ; cached : bigint
      ; swap_cached : bigint
      ; active : bigint
      ; inactive : bigint
      ; swap_total : bigint
      ; swap_free : bigint
      ; dirty : bigint
      ; writeback : bigint
      ; anon_pages : bigint
      ; mapped : bigint
      ; slab : bigint
      ; page_tables : bigint
      ; nfs_unstable : bigint
      ; bounce : bigint
      ; commit_limit : bigint
      ; committed_as : bigint
      ; vmalloc_total : bigint
      ; vmalloc_used : bigint
      ; vmalloc_chunk : bigint
      ; (* New kernel field in CentOS 7 *)
        mem_available : bigint option [@sexp.option]
      ; hugepages_total : bigint
      ; hugepages_free : bigint
      ; hugepages_rsvd : bigint
      ; hugepages_surp : bigint
      ; hugepagesize : bigint
      ; sreclaimable : bigint
      }
    [@@deriving fields ~getters, sexp_of]

    let of_lines_exn lines =
      let of_kb = Big_int.mult_int_big_int 1024 in
      let map =
        List.fold lines ~init:String.Map.empty ~f:(fun map line ->
          match
            String.strip line
            |> String.tr ~target:':' ~replacement:' '
            |> String.split ~on:' '
            |> List.filter ~f:(Fn.non String.is_empty)
          with
          | [ key; value; "kB" ] ->
            let data = Big_int.big_int_of_string value |> of_kb in
            Map.set map ~key ~data
          | [ key; value ] ->
            (* hugepage counts don't have kBs *)
            let data = Big_int.big_int_of_string value in
            Map.set map ~key ~data
          | _ -> (* ignore weird lines *) map)
      in
      let get k =
        match Map.find map k with
        | Some v -> v
        | None -> failwithf "meminfo_exn: cannot extract field %s" k ()
      in
      { mem_total = get "MemTotal"
      ; mem_free = get "MemFree"
      ; buffers = get "Buffers"
      ; cached = get "Cached"
      ; swap_cached = get "SwapCached"
      ; swap_free = get "SwapFree"
      ; active = get "Active"
      ; inactive = get "Inactive"
      ; swap_total = get "SwapTotal"
      ; dirty = get "Dirty"
      ; writeback = get "Writeback"
      ; anon_pages = get "AnonPages"
      ; mapped = get "Mapped"
      ; slab = get "Slab"
      ; page_tables = get "PageTables"
      ; nfs_unstable = get "NFS_Unstable"
      ; bounce = get "Bounce"
      ; commit_limit = get "CommitLimit"
      ; committed_as = get "Committed_AS"
      ; vmalloc_total = get "VmallocTotal"
      ; vmalloc_used = get "VmallocUsed"
      ; vmalloc_chunk = get "VmallocChunk"
      ; mem_available = Map.find map "MemAvailable"
      ; hugepages_total = get "HugePages_Total"
      ; hugepages_free = get "HugePages_Free"
      ; hugepages_rsvd = get "HugePages_Rsvd"
      ; hugepages_surp = get "HugePages_Surp"
      ; hugepagesize = get "Hugepagesize"
      ; sreclaimable = get "SReclaimable"
      }
    ;;

    let load_exn () = IO.read_lines "/proc/meminfo" >>| of_lines_exn

    let mem_available t =
      (* Use the MemAvailable field in newer kernels that have it, otherwise make a best
         efforts guess *)
      match t.mem_available with
      | Some ma -> ma
      | None ->
        let ( + ) = Big_int.add_big_int in
        t.mem_free + t.buffers + t.cached
    ;;
  end

  (** Parse /proc/stat because vmstat is dumb *)
  module Kstat = struct
    type index_t =
      | All
      | Number of int
    [@@deriving sexp_of]

    type cpu_t =
      { user : bigint
      ; nice : bigint
      ; sys : bigint
      ; idle : bigint
      ; iowait : bigint option
      ; irq : bigint option
      ; softirq : bigint option
      ; steal : bigint option
      ; guest : bigint option
      ; guest_nice : bigint option
      }
    [@@deriving sexp_of]

    type t = index_t * cpu_t

    let parse_line l =
      match l with
      | [ user; nice; sys; idle; iowait; irq; softirq; steal; guest; guest_nice ] ->
        (*=>= 2.6.33 (Documented in proc(5) with the kernel verisons below) *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = Some (Big_int.big_int_of_string iowait)
        ; irq = Some (Big_int.big_int_of_string irq)
        ; softirq = Some (Big_int.big_int_of_string softirq)
        ; steal = Some (Big_int.big_int_of_string steal)
        ; guest = Some (Big_int.big_int_of_string guest)
        ; guest_nice = Some (Big_int.big_int_of_string guest_nice)
        }
      | [ user; nice; sys; idle; iowait; irq; softirq; steal; guest ] ->
        (*=>= 2.6.24 *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = Some (Big_int.big_int_of_string iowait)
        ; irq = Some (Big_int.big_int_of_string irq)
        ; softirq = Some (Big_int.big_int_of_string softirq)
        ; steal = Some (Big_int.big_int_of_string steal)
        ; guest = Some (Big_int.big_int_of_string guest)
        ; guest_nice = None
        }
      | [ user; nice; sys; idle; iowait; irq; softirq; steal ] ->
        (*=>= 2.6.11 *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = Some (Big_int.big_int_of_string iowait)
        ; irq = Some (Big_int.big_int_of_string irq)
        ; softirq = Some (Big_int.big_int_of_string softirq)
        ; steal = Some (Big_int.big_int_of_string steal)
        ; guest = None
        ; guest_nice = None
        }
      | [ user; nice; sys; idle; iowait; irq; softirq ] ->
        (*=>= 2.6.0  *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = Some (Big_int.big_int_of_string iowait)
        ; irq = Some (Big_int.big_int_of_string irq)
        ; softirq = Some (Big_int.big_int_of_string softirq)
        ; steal = None
        ; guest = None
        ; guest_nice = None
        }
      | [ user; nice; sys; idle; iowait ] ->
        (*=>= 2.5.41  *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = Some (Big_int.big_int_of_string iowait)
        ; irq = None
        ; softirq = None
        ; steal = None
        ; guest = None
        ; guest_nice = None
        }
      | [ user; nice; sys; idle ] ->
        (* < 2.5.41 *)
        { user = Big_int.big_int_of_string user
        ; nice = Big_int.big_int_of_string nice
        ; sys = Big_int.big_int_of_string sys
        ; idle = Big_int.big_int_of_string idle
        ; iowait = None
        ; irq = None
        ; softirq = None
        ; steal = None
        ; guest = None
        ; guest_nice = None
        }
      | _ -> failwith "No idea what this line is"
    ;;

    let load_exn () =
      IO.read_lines "/proc/stat"
      >>| List.fold ~init:[] ~f:(fun accum line ->
        match
          String.strip line
          |> String.split ~on:' '
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | "cpu" :: rest -> (All, parse_line rest) :: accum
        | cpuidx :: rest ->
          if String.is_prefix ~prefix:"cpu" cpuidx
          then (
            let idx = String.slice cpuidx 3 (String.length cpuidx) in
            (Number (Int.of_string idx), parse_line rest) :: accum)
          else accum
        | _ -> accum
        (* ignore weird lines *))
    ;;
  end

  module Loadavg = struct
    type t =
      { one : float
      ; five : float
      ; fifteen : float
      }
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

    (* /proc/loadavg has just 1 line nearly all the time, but occasionally there's an
       extra blank line. just be extra forgiving and grab only the first line. *)
    let load_exn () =
      match%map IO.read_lines "/proc/loadavg" with
      | line :: _rest ->
        (match String.split line ~on:' ' with
         | l1 :: l5 :: l15 :: _rest ->
           let one, five, fifteen =
             Float.of_string l1, Float.of_string l5, Float.of_string l15
           in
           { one; five; fifteen }
         | _ -> failwithf "couldn't parse load average from line: %s" line ())
      | [] -> failwith "no lines read from /proc/loadavg!"
    ;;
  end

  module Net = struct
    (** Mirrors the safety checks of [Unix_extended.Inet_port], but is just an int. This
        is so that we can not require depending on [unix_extended], which is not in
        foundation, but leave an easy path towards removing this type if it ever becomes
        foundation. *)
    module Inet_port = struct
      type t = int [@@deriving sexp_of, equal ~localize]

      let of_int_exn x =
        if x > 0 && x < 65536
        then x
        else failwith (Core.sprintf "%d is not a valid port number." x)
      ;;

      let of_int x =
        try Some (of_int_exn x) with
        | _ -> None
      ;;
    end

    (** handles hexadecimal types (integer, internet address, port) as presented in
        /proc/net/[{tcp,udp,raw}][{,6}] *)
    module Hexstr : sig
      val to_int : string -> int

      (* the "endianness" of values in /proc/net/* is a bit confusing, so we need specific
         function for each type. We should probably check if these values are presented in
         the same way in a big-endian host *)

      val to_inetaddr : string -> Unix.Inet_addr.t

      (* exception for /proc/net/igmp6 *)

      val printk_pi6_to_inetaddr : string -> Unix.Inet_addr.t
      val to_inetport_exn : string -> Inet_port.t
      val to_inetport : string -> Inet_port.t option
    end = struct
      (* Assert the system is little-endian both at compile time *and* runtime. I would
         guess the two are equivalent, since we don't really do cross-compilation, but
         it's cheap to verify. *)
      let verify_endianness here =
        if Sys.big_endian
        then
          raise_s
            [%message
              "We suspect this code is incorrect on big-endian systems"
                (Sys.big_endian : bool)
                (here : Source_code_position.t)]
      ;;

      (* If you're hitting this test failure, here are some possible resolutions:
         - You actually need this code. In that case you should first verify it produces
           correct results (and fix it if it does not).
         - You don't need this code, but you're compiling it anyway. In that case you
           could remove the test and people who use the code can just rely on the runtime
           assertions, but that seems kinda sad. Consider doing the previous bullet point
           anyway, out of the kindness of your heart :) *)
      let%test "this test fails if we compile code assuming little-endianness on a \
                big-endian system"
        =
        not Sys.big_endian
      ;;

      let to_charpairs s =
        String.to_list s |> List.chunks_of ~length:2 |> List.map ~f:String.of_char_list
      ;;

      let to_int s = Int.of_string ("0x" ^ s)

      let to_ipv4 s =
        verify_endianness [%here];
        (match to_charpairs s with
         | [ a0; a1; a2; a3 ] -> [ a3; a2; a1; a0 ]
         | _ -> failwithf "Invalid IPv4 address %S" s ())
        |> List.map ~f:(fun v -> to_int v |> Int.to_string)
        |> String.concat ~sep:"."
        |> Unix.Inet_addr.of_string
      ;;

      let to_ipv6 s =
        verify_endianness [%here];
        (match to_charpairs s with
         | [ a0; a1; a2; a3; b0; b1; b2; b3; c0; c1; c2; c3; d0; d1; d2; d3 ] ->
           [ a3 ^ a2; a1 ^ a0; b3 ^ b2; b1 ^ b0; c3 ^ c2; c1 ^ c0; d3 ^ d2; d1 ^ d0 ]
         | _ -> failwithf "Invalid IPv6 address %S" s ())
        |> String.concat ~sep:":"
        |> Unix.Inet_addr.of_string
      ;;

      let to_inetaddr s =
        match String.length s with
        | 8 -> to_ipv4 s
        | 32 -> to_ipv6 s
        | _ -> failwithf "Invalid IP address %S" s ()
      ;;

      (* Parses an IPv6 address in printk's %pi6 format.

         https://www.kernel.org/doc/Documentation/printk-formats.txt
      *)
      let printk_pi6_to_inetaddr s =
        String.to_list s
        |> List.groupi ~break:(fun i _ _ -> i % 4 = 0)
        |> List.map ~f:String.of_char_list
        |> String.concat ~sep:":"
        |> Unix.Inet_addr.of_string
      ;;

      let to_inetport_exn s =
        verify_endianness [%here];
        to_int s |> Inet_port.of_int_exn
      ;;

      let to_inetport s =
        verify_endianness [%here];
        to_int s |> Inet_port.of_int
      ;;
    end

    module Dev = struct
      type t =
        { iface : string
        ; rx_bytes : int
        ; rx_packets : int
        ; rx_errs : int
        ; rx_drop : int
        ; rx_fifo : int
        ; rx_frame : int
        ; rx_compressed : bool
        ; rx_multicast : bool
        ; tx_bytes : int
        ; tx_packets : int
        ; tx_errs : int
        ; tx_drop : int
        ; tx_fifo : int
        ; tx_colls : int
        ; tx_carrier : int
        ; tx_compressed : bool
        }
      [@@deriving sexp_of]

      let eval_mul_comp rx_tx =
        match rx_tx with
        | 0 -> false
        | 1 -> true
        | _ -> failwithf "Proc.Net.Dev error : value is %d, expected 0 or 1." rx_tx ()
      ;;

      let of_string str =
        let s = String.strip in
        let ios str = Int.of_string str in
        match String.split ~on:'\t' str with
        | [ iface
          ; rx_bytes
          ; rx_packets
          ; rx_errs
          ; rx_drop
          ; rx_fifo
          ; rx_frame
          ; rx_compressed
          ; rx_multicast
          ; tx_bytes
          ; tx_packets
          ; tx_errs
          ; tx_drop
          ; tx_fifo
          ; tx_colls
          ; tx_carrier
          ; tx_compressed
          ] ->
          Some
            { iface = s iface
            ; rx_bytes = ios (s rx_bytes)
            ; rx_packets = ios (s rx_packets)
            ; rx_errs = ios (s rx_errs)
            ; rx_drop = ios (s rx_drop)
            ; rx_fifo = ios (s rx_fifo)
            ; rx_frame = ios (s rx_frame)
            ; rx_compressed = eval_mul_comp (ios rx_compressed)
            ; rx_multicast = eval_mul_comp (ios rx_multicast)
            ; tx_bytes = ios (s tx_bytes)
            ; tx_packets = ios (s tx_packets)
            ; tx_errs = ios (s tx_errs)
            ; tx_drop = ios (s tx_drop)
            ; tx_fifo = ios (s tx_fifo)
            ; tx_colls = ios (s tx_colls)
            ; tx_carrier = ios (s tx_carrier)
            ; tx_compressed = eval_mul_comp (ios tx_compressed)
            }
        | _ -> failwithf "Net.Dev.of_string: unsupported format: %s" str ()
      ;;

      (* add interfaces () to get a list of all interfaces on box *)
      let interfaces () =
        IO.read_lines "/proc/net/dev"
        >>| List.filter_map ~f:(fun line ->
          String.lsplit2 line ~on:':'
          |> Option.map ~f:(fun (before, _after) ->
            String.lstrip ~drop:Char.is_whitespace before))
      ;;
    end

    module Route = struct
      module Flags = struct
        let up = Int63.of_int 0x0001
        let gateway = Int63.of_int 0x0002
        let host = Int63.of_int 0x0004
        let reinstate = Int63.of_int 0x0008
        let dynamic = Int63.of_int 0x0010
        let modified = Int63.of_int 0x0020
        let mtu = Int63.of_int 0x0040
        let window = Int63.of_int 0x0080
        let irtt = Int63.of_int 0x0100
        let reject = Int63.of_int 0x0200
        let static = Int63.of_int 0x0400
        let xresolve = Int63.of_int 0x0800
        let noforward = Int63.of_int 0x1000
        let throw = Int63.of_int 0x2000
        let nopmtudisc = Int63.of_int 0x4000

        let known =
          [ up, "up"
          ; gateway, "gateway"
          ; host, "host"
          ; reinstate, "reinstate"
          ; dynamic, "dynamic"
          ; modified, "modified"
          ; mtu, "mtu"
          ; window, "window"
          ; irtt, "irtt"
          ; reject, "reject"
          ; static, "static"
          ; xresolve, "xresolve"
          ; noforward, "noforward"
          ; throw, "throw"
          ; nopmtudisc, "nopmtudisc"
          ]
        ;;

        include Flags.Make (struct
            let allow_intersecting = true
            let should_print_error = true
            let known = known
            let remove_zero_flags = false
          end)

        (* there are other RTF_ constants, we think they are IPv6-only and so not
           relevant, but it won't crash your program to ignore them even if they do appear
        *)
      end

      type t =
        { iface : string
        ; destination : Unix.Inet_addr.t
        ; gateway : Unix.Inet_addr.t
        ; flags : Flags.t
        ; refcnt : int
        ; use : int
        ; metric : int
        ; mask : Unix.Inet_addr.t
        ; mtu : int
        ; window : int
        ; irtt : int
        }
      [@@deriving sexp_of, fields ~getters]

      let of_line_exn line =
        match
          String.split_on_chars line ~on:[ '\t'; ' ' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | [ iface
          ; destination
          ; gateway
          ; flags
          ; refcnt
          ; use
          ; metric
          ; mask
          ; mtu
          ; window
          ; irtt
          ] ->
          let create_entry () =
            { iface
            ; destination = Hexstr.to_inetaddr destination
            ; gateway = Hexstr.to_inetaddr gateway
            ; flags = Flags.of_int (Hexstr.to_int flags)
            ; refcnt = Int.of_string refcnt
            ; use = Int.of_string use
            ; metric = Int.of_string metric
            ; mask = Hexstr.to_inetaddr mask
            ; mtu = Int.of_string mtu
            ; window = Int.of_string window
            ; irtt = Int.of_string irtt
            }
          in
          (match create_entry () with
           | exception error ->
             raise_s
               [%message
                 "unable to parse line elements"
                   (error : exn)
                   (iface : string)
                   (destination : string)
                   (gateway : string)
                   (flags : string)
                   (refcnt : string)
                   (use : string)
                   (metric : string)
                   (mask : string)
                   (mtu : string)
                   (window : string)
                   (irtt : string)]
           | entry -> entry)
        | parts -> raise_s [%message "unable to parse line" (parts : string list)]
      ;;

      let of_line line =
        try Some (of_line_exn line) with
        | _ -> None
      ;;

      let load_exn () =
        IO.read_lines "/proc/net/route" >>| List.tl_exn >>| List.map ~f:of_line_exn
      ;;

      let default () =
        let default_route = Unix.Inet_addr.of_string "0.0.0.0" in
        let%map lst = load_exn () in
        match
          List.filter_map lst ~f:(fun x ->
            if Unix.Inet_addr.equal x.destination default_route
            then Some x.gateway
            else None)
        with
        | [ x ] -> x
        | [] -> failwith "No default gateway set?"
        | unk ->
          failwithf
            "Looks like there are > 1 gateway set: %s !"
            (String.concat ~sep:", " (List.map unk ~f:Unix.Inet_addr.to_string))
            ()
      ;;
    end

    module Ipproto = struct
      module Stable = Stable.Net.Ipproto

      type t = Stable.V1.t =
        | ICMP
        | IGMP
        | IPIP
        | TCP
        | EGP
        | PUP
        | UDP
        | IDP
        | TP
        | DCCP
        | IPV6
        | RSVP
        | GRE
        | ESP
        | AH
        | MTP
        | BEETPH
        | ENCAP
        | PIM
        | COMP
        | SCTP
        | UDPLITE
        | RAW
        | Unknown of int
      [@@deriving sexp_of, variants, compare ~localize, equal ~localize, hash]

      let to_int t =
        match t with
        | ICMP -> 1
        | IGMP -> 2
        | IPIP -> 4
        | TCP -> 6
        | EGP -> 8
        | PUP -> 12
        | UDP -> 17
        | IDP -> 22
        | TP -> 29
        | DCCP -> 33
        | IPV6 -> 41
        | RSVP -> 46
        | GRE -> 47
        | ESP -> 50
        | AH -> 51
        | MTP -> 92
        | BEETPH -> 94
        | ENCAP -> 98
        | PIM -> 103
        | COMP -> 108
        | SCTP -> 132
        | UDPLITE -> 136
        | RAW -> 255
        | Unknown i -> i
      ;;

      let of_int i =
        match i with
        | 1 -> ICMP
        | 2 -> IGMP
        | 4 -> IPIP
        | 6 -> TCP
        | 8 -> EGP
        | 12 -> PUP
        | 17 -> UDP
        | 22 -> IDP
        | 29 -> TP
        | 33 -> DCCP
        | 41 -> IPV6
        | 46 -> RSVP
        | 47 -> GRE
        | 50 -> ESP
        | 51 -> AH
        | 92 -> MTP
        | 94 -> BEETPH
        | 98 -> ENCAP
        | 103 -> PIM
        | 108 -> COMP
        | 132 -> SCTP
        | 136 -> UDPLITE
        | 255 -> RAW
        | i -> Unknown i
      ;;

      let to_string t = Variants.to_name t
    end

    module Tcp_state = struct
      type t =
        | TCP_ESTABLISHED
        | TCP_SYN_SENT
        | TCP_SYN_RECV
        | TCP_FIN_WAIT1
        | TCP_FIN_WAIT2
        | TCP_TIME_WAIT
        | TCP_CLOSE
        | TCP_CLOSE_WAIT
        | TCP_LAST_ACK
        | TCP_LISTEN
        | TCP_CLOSING
        | Unknown of int
      [@@deriving sexp_of, equal ~localize]

      let to_int = function
        | TCP_ESTABLISHED -> 1
        | TCP_SYN_SENT -> 2
        | TCP_SYN_RECV -> 3
        | TCP_FIN_WAIT1 -> 4
        | TCP_FIN_WAIT2 -> 5
        | TCP_TIME_WAIT -> 6
        | TCP_CLOSE -> 7
        | TCP_CLOSE_WAIT -> 8
        | TCP_LAST_ACK -> 9
        | TCP_LISTEN -> 10
        | TCP_CLOSING -> 11
        | Unknown i -> i
      ;;

      let of_int = function
        | 1 -> TCP_ESTABLISHED
        | 2 -> TCP_SYN_SENT
        | 3 -> TCP_SYN_RECV
        | 4 -> TCP_FIN_WAIT1
        | 5 -> TCP_FIN_WAIT2
        | 6 -> TCP_TIME_WAIT
        | 7 -> TCP_CLOSE
        | 8 -> TCP_CLOSE_WAIT
        | 9 -> TCP_LAST_ACK
        | 10 -> TCP_LISTEN
        | 11 -> TCP_CLOSING
        | i -> Unknown i
      ;;

      let of_hex s = of_int (Hexstr.to_int s)
    end

    module Udp_state = struct
      type t =
        | Default_destination_assigned
        | No_default_destination_assigned
        | Unknown of int
      [@@deriving sexp_of, equal ~localize]

      let to_int = function
        | Default_destination_assigned -> 1
        | No_default_destination_assigned -> 7
        | Unknown i -> i
      ;;

      let of_int = function
        | 1 -> Default_destination_assigned
        | 7 -> No_default_destination_assigned
        | i -> Unknown i
      ;;

      let of_hex s = of_int (Hexstr.to_int s)
    end

    module Raw_state = struct
      type t =
        | Default_destination_assigned
        | No_default_destination_assigned
        | Unknown of int
      [@@deriving sexp_of, equal ~localize]

      let to_int = function
        | Default_destination_assigned -> 1
        | No_default_destination_assigned -> 7
        | Unknown i -> i
      ;;

      let of_int = function
        | 1 -> Default_destination_assigned
        | 7 -> No_default_destination_assigned
        | i -> Unknown i
      ;;

      let of_hex s = of_int (Hexstr.to_int s)
    end

    module Socket_state = struct
      type t =
        | Tcp of Tcp_state.t
        | Udp of Udp_state.t
        | Raw of Raw_state.t
      [@@deriving sexp_of, equal ~localize]
    end

    type 'state t =
      { sl : int
      ; local_address : Core_unix.Inet_addr.t
      ; local_port : Inet_port.t
      ; remote_address : Core_unix.Inet_addr.t
      ; remote_port : Inet_port.t option
      ; state : 'state
      ; tx_queue : int
      ; rx_queue : int
      ; tr : int
      ; tm_when : int
      ; retrnsmt : int
      ; uid : int
      ; timeout : int
      ; inode : Process.Inode.t
      ; rest : string
      }
    [@@deriving sexp_of, fields ~getters, equal ~localize]

    let map_state t ~f = { t with state = f t.state }

    module type Inet_l4_proto = sig
      type state
      type nonrec t = state t [@@deriving sexp_of]

      val socket_domain : Unix.socket_domain
      val ipproto : Ipproto.t
      val of_line : string -> t option
      val of_line_exn : string -> t
      val load_exn : unit -> t list IO.io
    end

    module Inet_l4_proto (M : sig
        type state [@@deriving sexp_of, equal ~localize]

        val state_of_hex : string -> state
        val file : string
        val socket_domain : Unix.socket_domain
        val ipproto : Ipproto.t
      end) =
    struct
      type nonrec t = M.state t [@@deriving sexp_of, equal ~localize]

      let socket_domain = M.socket_domain
      let ipproto = M.ipproto

      let of_line_exn line =
        match
          String.split_on_chars line ~on:[ ' '; ':' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | sl
          :: local_address
          :: local_port
          :: remote_address
          :: remote_port
          :: state
          :: tx_queue
          :: rx_queue
          :: tr
          :: tm_when
          :: retrnsmt
          :: uid
          :: timeout
          :: inode
          :: rest ->
          { sl = Int.of_string sl
          ; local_address = Hexstr.to_inetaddr local_address
          ; local_port = Hexstr.to_inetport_exn local_port
          ; remote_address = Hexstr.to_inetaddr remote_address
          ; remote_port = Hexstr.to_inetport remote_port
          ; state = M.state_of_hex state
          ; tx_queue = Hexstr.to_int tx_queue
          ; rx_queue = Hexstr.to_int rx_queue
          ; tr = Hexstr.to_int tr
          ; tm_when = Hexstr.to_int tm_when
          ; retrnsmt = Hexstr.to_int retrnsmt
          ; uid = Int.of_string uid
          ; timeout = Int.of_string timeout
          ; inode = Process.Inode.of_string inode
          ; rest = String.concat ~sep:" " rest
          }
        | _ -> failwith "Unable to parse this line!\n%!"
      ;;

      let of_line line =
        try Some (of_line_exn line) with
        | _ -> None
      ;;

      let load_exn () =
        let%map lines =
          IO.try_with_handler
            ~here:[%here]
            ~f:(fun () ->
              let%map lines = IO.read_lines M.file in
              Some lines)
            ~handler:(function
              (* M.file doesn't exist, most likely this means the kernel feature wasn't
                 enabled (i.e. there can't possibly be any connections), so we suppress
                 the error and return an empty list instead. The corner case where /proc
                 is not mounted might match this case too. *)
              | Unix.Unix_error (ENOENT, _, _)
              (* Blocking_io doesn't raise [Unix.Unix_error] so we can't match the ENOENT
                 case. Matching on Sys_error might also capture other failures like
                 permissions (or selinux) setup in a way that we can't read them. These
                 seem pretty unlikely so the simplification of conflating them seems ok. *)
              | Sys_error _ -> None
              | e -> raise e)
        in
        match lines with
        | None -> []
        | Some lines -> List.map (List.tl_exn lines) ~f:of_line_exn
      ;;
    end

    module Tcp = Inet_l4_proto (struct
        type state = Tcp_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Tcp_state.of_hex
        let file = "/proc/net/tcp"
        let socket_domain = Unix.PF_INET
        let ipproto = Ipproto.TCP
      end)

    (* testing Tcp only, since Udp and Raw are almost identical modules *)

    let%test _ =
      Tcp.of_line
        "  40: 458719AC:9342 CC1619AC:0016 01 00000000:00000000 02:000296F0 00000000 \
         12021        0      64400541 2 ffff88022c777400 20 3 0 10 -1"
      |> Option.is_some
    ;;

    (* Port 0 on the other side *)
    let%test _ =
      Tcp.of_line
        "  31: 0100007F:177E 00000000:0000 0A 00000000:00000000 00:00000000 00000000 \
         12021        0 778748 1 ffff8102edd1ad00 3000 0 0 2 -1"
      |> Option.is_some
    ;;

    let%test _ =
      [%equal: Tcp_state.t t option]
        (Tcp.of_line
           "  40: 458719AC:9342 CC1619AC:0016 01 00000000:00000000 02:000296F0 00000000 \
            12021        0      64400541 2 ffff88022c777400 20 3 0 10 -1")
        (Some
           { sl = 40
           ; local_address = Unix.Inet_addr.of_string "172.25.135.69"
           ; local_port = Inet_port.of_int_exn 37698
           ; remote_address = Unix.Inet_addr.of_string "172.25.22.204"
           ; remote_port = Some (Inet_port.of_int_exn 22)
           ; state = Tcp_state.TCP_ESTABLISHED
           ; tx_queue = 0
           ; rx_queue = 0
           ; tr = 2
           ; tm_when = 169712
           ; retrnsmt = 0
           ; uid = 12021
           ; timeout = 0
           ; inode = Process.Inode.of_string "64400541"
           ; rest = "2 ffff88022c777400 20 3 0 10 -1"
           })
    ;;

    (* Port 0 on the other side *)
    let%test _ =
      [%equal: Tcp_state.t t option]
        (Tcp.of_line
           "  31: 0100007F:177E 00000000:0000 0A 00000000:00000000 00:00000000 00000000 \
            12021        0 778748 1 ffff8102edd1ad00 3000 0 0 2 -1")
        (Some
           { sl = 31
           ; local_address = Unix.Inet_addr.of_string "127.0.0.1"
           ; local_port = Inet_port.of_int_exn 6014
           ; remote_address = Unix.Inet_addr.of_string "0.0.0.0"
           ; remote_port = None
           ; state = Tcp_state.TCP_LISTEN
           ; tx_queue = 0
           ; rx_queue = 0
           ; tr = 0
           ; tm_when = 0
           ; retrnsmt = 0
           ; uid = 12021
           ; timeout = 0
           ; inode = Process.Inode.of_string "778748"
           ; rest = "1 ffff8102edd1ad00 3000 0 0 2 -1"
           })
    ;;

    module Udp = Inet_l4_proto (struct
        type state = Udp_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Udp_state.of_hex
        let file = "/proc/net/udp"
        let socket_domain = Unix.PF_INET
        let ipproto = Ipproto.UDP
      end)

    module Raw = Inet_l4_proto (struct
        type state = Raw_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Raw_state.of_hex
        let file = "/proc/net/raw"
        let socket_domain = Unix.PF_INET
        let ipproto = Ipproto.RAW
      end)

    module Tcp6 = Inet_l4_proto (struct
        type state = Tcp_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Tcp_state.of_hex
        let file = "/proc/net/tcp6"
        let socket_domain = Unix.PF_INET6
        let ipproto = Ipproto.TCP
      end)

    module Udp6 = Inet_l4_proto (struct
        type state = Udp_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Udp_state.of_hex
        let file = "/proc/net/udp6"
        let socket_domain = Unix.PF_INET6
        let ipproto = Ipproto.UDP
      end)

    module Raw6 = Inet_l4_proto (struct
        type state = Raw_state.t [@@deriving sexp_of, equal ~localize]

        let state_of_hex = Raw_state.of_hex
        let file = "/proc/net/raw6"
        let socket_domain = Unix.PF_INET6
        let ipproto = Ipproto.RAW
      end)

    module Arp = struct
      module Hardware_type = struct
        type t =
          | NETROM
          | ETHER
          | EETHER
          | AX25
          | PRONET
          | CHAOS
          | IEEE802
          | ARCNET
          | APPLETLK
          | DLCI
          | ATM
          | METRICOM
          | IEEE1394
          | EUI64
          | INFINIBAND
          | Unknown of int
        [@@deriving sexp_of, equal ~localize]

        let to_int = function
          | NETROM -> 0
          | ETHER -> 1
          | EETHER -> 2
          | AX25 -> 3
          | PRONET -> 4
          | CHAOS -> 5
          | IEEE802 -> 6
          | ARCNET -> 7
          | APPLETLK -> 8
          | DLCI -> 15
          | ATM -> 19
          | METRICOM -> 23
          | IEEE1394 -> 24
          | EUI64 -> 27
          | INFINIBAND -> 32
          | Unknown i -> i
        ;;

        let of_int = function
          | 0 -> NETROM
          | 1 -> ETHER
          | 2 -> EETHER
          | 3 -> AX25
          | 4 -> PRONET
          | 5 -> CHAOS
          | 6 -> IEEE802
          | 7 -> ARCNET
          | 8 -> APPLETLK
          | 15 -> DLCI
          | 19 -> ATM
          | 23 -> METRICOM
          | 24 -> IEEE1394
          | 27 -> EUI64
          | 32 -> INFINIBAND
          | i -> Unknown i
        ;;
      end

      module Flags = struct
        let lookup_complete = Int63.of_int 0x02
        let permanent_entry = Int63.of_int 0x04
        let publish_entry = Int63.of_int 0x08
        let trailers_requested = Int63.of_int 0x10
        let use_a_netmask = Int63.of_int 0x20
        let do_not_answer = Int63.of_int 0x40

        let known =
          [ lookup_complete, "lookup_complete"
          ; permanent_entry, "permanent_entry"
          ; publish_entry, "publish_entry"
          ; trailers_requested, "trailers_requested"
          ; use_a_netmask, "use_a_netmask"
          ; do_not_answer, "do_not_answer"
          ]
        ;;

        include Flags.Make (struct
            let allow_intersecting = true
            let should_print_error = true
            let known = known
            let remove_zero_flags = false
          end)
      end

      type t =
        { ip_address : Unix.Inet_addr.t
        ; hw_type : Hardware_type.t
        ; flags : Flags.t
        ; hw_address : Mac_address.t
        ; device : string
        }
      [@@deriving sexp_of]

      let of_line_exn line =
        match
          String.split_on_chars line ~on:[ '\t'; ' ' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | [ ip_address; hw_type; flags; hw_address; mask; device ] ->
          let create_entry () =
            { ip_address = Unix.Inet_addr.of_string ip_address
            ; hw_type = Hardware_type.of_int (Int.of_string hw_type)
            ; flags = Int.of_string flags |> Flags.of_int
            ; hw_address = Mac_address.of_string hw_address
            ; device
            }
          in
          (match create_entry () with
           | exception error ->
             raise_s
               [%message
                 "Unable to parse components of /proc/net/arp"
                   (error : exn)
                   (ip_address : string)
                   (hw_type : string)
                   (flags : string)
                   (hw_address : string)
                   (mask : string)
                   (device : string)]
           | entry -> entry)
        | parts ->
          raise_s
            [%message "Unable to parse line from /proc/net/arp" (parts : string list)]
      ;;

      let of_line line =
        try Some (of_line_exn line) with
        | _ -> None
      ;;

      let load_exn () =
        IO.read_lines "/proc/net/arp" >>| List.tl_exn >>| List.map ~f:of_line_exn
      ;;
    end

    module Igmp = struct
      type t =
        { idx : int
        ; device : string
        ; querier : int option
        ; group : Unix.Inet_addr.t
        ; users : int
        ; timer_running : bool
        ; timer : int
        ; reporter : int
        }
      [@@deriving sexp_of]

      type header =
        { idx : int
        ; device : string
        ; count : int
        ; querier : int option
        }

      let of_header s =
        match
          String.split_on_chars s ~on:[ '\t'; ' '; ':' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | [ idx; device; count; querier ] ->
          let create_entry () =
            { idx = Int.of_string idx
            ; device
            ; count = Int.of_string count
            ; querier =
                (match querier with
                 | "NONE" -> None
                 | "V1" -> Some 1
                 | "V2" -> Some 2
                 | "V3" -> Some 3
                 | _ -> raise_s [%message "invalid querier value" (querier : string)])
            }
          in
          (match create_entry () with
           | exception error ->
             raise_s
               [%message
                 "unable to parse header elements"
                   (error : exn)
                   (idx : string)
                   (device : string)
                   (count : string)
                   (querier : string)]
           | entry -> entry)
        | parts -> raise_s [%message "unable to parse header" (parts : string list)]
      ;;

      let of_line s ~idx ~device ~querier =
        match
          String.split_on_chars s ~on:[ '\t'; ' '; ':' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | [ group; users; timer_running; timer; reporter ] ->
          let create_entry () =
            { idx
            ; device
            ; querier
            ; group = Hexstr.to_inetaddr group
            ; users = Int.of_string users
            ; timer_running =
                (* converting to boolean in the C meaning of "different from zero" *)
                Int.of_string timer_running <> 0
            ; timer = Hexstr.to_int timer
            ; reporter = Int.of_string reporter
            }
          in
          (match create_entry () with
           | exception error ->
             raise_s
               [%message
                 "unable to parse line elements"
                   (error : exn)
                   (group : string)
                   (users : string)
                   (timer_running : string)
                   (timer : string)
                   (reporter : string)]
           | entry -> entry)
        | parts -> raise_s [%message "unable to parse line" (parts : string list)]
      ;;

      let rec of_lines lst =
        match lst with
        | [] -> []
        | hd :: tl ->
          let { idx; device; count; querier } = of_header hd in
          let #(memberships, tl) = List.split_n tl count in
          List.map memberships ~f:(of_line ~idx ~device ~querier) @ of_lines tl
      ;;

      let load_exn () = IO.read_lines "/proc/net/igmp" >>| List.tl_exn >>| of_lines
    end

    (* see kernel's include/net/if_inet6.h *)
    module Mca_flags = struct
      let timer_running = Int63.of_int 0x01
      let last_reporter = Int63.of_int 0x02
      let loaded = Int63.of_int 0x04
      let noreport = Int63.of_int 0x08
      let gsquery = Int63.of_int 0x10

      let known =
        [ timer_running, "timer_running"
        ; last_reporter, "last_reporter"
        ; loaded, "loaded"
        ; noreport, "noreport"
        ; gsquery, "gsquery"
        ]
      ;;

      include Flags.Make (struct
          let allow_intersecting = true
          let should_print_error = true
          let known = known
          let remove_zero_flags = false
        end)
    end

    module Igmp6 = struct
      type t =
        { idx : int
        ; device : string
        ; group : Unix.Inet_addr.t
        ; users : int
        ; flags : Mca_flags.t
        ; timer : int
        }
      [@@deriving sexp_of]

      let of_line_exn s =
        match
          String.split_on_chars s ~on:[ '\t'; ' '; ':' ]
          |> List.filter ~f:(Fn.non String.is_empty)
        with
        | [ idx; device; group; users; flags; timer ] ->
          let create_entry () =
            { idx = Int.of_string idx
            ; device
            ; group = Hexstr.printk_pi6_to_inetaddr group
            ; users = Int.of_string users
            ; flags = Hexstr.to_int flags |> Mca_flags.of_int
            ; timer = Int.of_string timer
            }
          in
          (match create_entry () with
           | exception error ->
             raise_s
               [%message
                 "unable to parse line elements"
                   (error : exn)
                   (idx : string)
                   (group : string)
                   (users : string)
                   (flags : string)
                   (timer : string)]
           | entry -> entry)
        | parts -> raise_s [%message "unable to parse line" (parts : string list)]
      ;;

      let of_line line =
        try Some (of_line_exn line) with
        | _ -> None
      ;;

      let load_exn () = IO.read_lines "/proc/net/igmp6" >>| List.map ~f:of_line_exn
    end
  end

  module Mount = struct
    type t =
      { spec : string (* block device special name *)
      ; file : string (* fs path prefix *)
      ; vfstype : string (* ext3, nfs, etc. *)
      ; mntops : string list (* mount options -o *)
      ; freq : int (* dump frequency *)
      ; (* pass number of parallel dump *)
        passno : int
      }
    [@@deriving fields ~getters, sexp_of]

    let of_string s =
      match String.split ~on:' ' s |> List.filter ~f:(Fn.non String.is_empty) with
      | [ spec; file; vfstype; mntops; freq; passno ] ->
        { spec
        ; file
        ; vfstype
        ; mntops = String.split ~on:',' mntops
        ; freq = Int.of_string freq
        ; passno = Int.of_string passno
        }
      | _ -> failwithf "Mount.of_string: unsupported format: %s" s ()
    ;;
  end

  module Diskstat = struct
    module Stable = Stable.Diskstat

    type t = Stable.V1.t =
      { major : int (* major device number *)
      ; minor : int (* minor device number *)
      ; device_name : string (* device name *)
      ; reads : int64 (* reads successfully completed *)
      ; reads_merged : int64 (* reads merged *)
      ; sectors_read : int64 (* sectors read (512 bytes always) *)
      ; read_time : int (* time spent reading (ms) *)
      ; writes : int64 (* writes successfully completed *)
      ; writes_merged : int64 (* writes merged *)
      ; sectors_written : int64 (* sectors written (512 bytes always) *)
      ; write_time : int (* time spent writing (ms) *)
      ; io_in_progress : int (* number of I/O operations currently in progress *)
      ; io_time : int (* ms spent doing I/O *)
      ; weighted_io_time : int (* weighted ms spent doing I/O *)
      ; discards : int64 option (* discards completed successfully *)
      ; discards_merged : int64 option (* discards merged *)
      ; sectors_discarded : int64 option (* sectors discarded (512 bytes) *)
      ; discard_time : int option (* ms spent discarding *)
      ; flushes : int64 option (* flush requests completed successfully *)
      ; flush_time : int option (* ms spent flushing *)
      }
    [@@deriving fields ~getters, sexp_of]

    (* Wrap the top-half of the unsigned 64-bit range into negative 64-bit. The conversion
       is a bit ugly since we can't represent unsigned 64-bit values natively (yet). *)
    let int64_of_string_uint64 s =
      let bi = Big_int.big_int_of_string s
      and max_uint64_plus_one = Big_int.power_int_positive_int 2 64
      and max_signed = Big_int.big_int_of_int64 Int64.max_value in
      if Big_int.ge_big_int bi max_uint64_plus_one
      then failwith [%string "int64_of_string_uint64: too big %{s}"]
      else if Big_int.gt_big_int bi max_signed
      then Big_int.sub_big_int bi max_uint64_plus_one |> Big_int.int64_of_big_int
      else Big_int.int64_of_big_int bi
    ;;

    let of_string s =
      match String.split ~on:' ' s |> List.filter ~f:(Fn.non String.is_empty) with
      | major
        :: minor
        :: device_name
        :: reads
        :: reads_merged
        :: sectors_read
        :: read_time
        :: writes
        :: writes_merged
        :: sectors_written
        :: write_time
        :: io_in_progress
        :: io_time
        :: weighted_io_time
        :: more_fields ->
        let major, minor = Tuple2.map ~f:int_of_string (major, minor) in
        let reads, reads_merged, sectors_read =
          Tuple3.map ~f:int64_of_string_uint64 (reads, reads_merged, sectors_read)
        in
        let read_time = int_of_string read_time in
        let writes, writes_merged, sectors_written =
          Tuple3.map ~f:int64_of_string_uint64 (writes, writes_merged, sectors_written)
        in
        let write_time = int_of_string write_time in
        let io_in_progress, io_time, weighted_io_time =
          Tuple3.map ~f:int_of_string (io_in_progress, io_time, weighted_io_time)
        in
        let ( discards
            , discards_merged
            , sectors_discarded
            , discard_time
            , flushes
            , flush_time )
          =
          match more_fields with
          | discards
            :: discards_merged
            :: sectors_discarded
            :: discard_time
            :: more_fields ->
            let discards, discards_merged, sectors_discarded =
              Tuple3.map
                ~f:(Fn.compose Option.return int64_of_string_uint64)
                (discards, discards_merged, sectors_discarded)
            and discard_time = Some (int_of_string discard_time) in
            let flushes, flush_time =
              match more_fields with
              | flushes :: flush_time :: _more_fields ->
                Some (int64_of_string_uint64 flushes), Some (int_of_string flush_time)
              | _ -> None, None
            in
            ( discards
            , discards_merged
            , sectors_discarded
            , discard_time
            , flushes
            , flush_time )
          | _ -> None, None, None, None, None, None
        in
        { major
        ; minor
        ; device_name
        ; reads
        ; reads_merged
        ; sectors_read
        ; read_time
        ; writes
        ; writes_merged
        ; sectors_written
        ; write_time
        ; io_in_progress
        ; io_time
        ; weighted_io_time
        ; discards
        ; discards_merged
        ; sectors_discarded
        ; discard_time
        ; flushes
        ; flush_time
        }
      | _ -> raise_s [%message "unexpected formatting in diskstats" (s : string)]
    ;;
  end

  type 'a with_process_load_args = ?load_tasks:bool -> 'a

  let get_all_procs ?load_tasks () =
    IO.readdir "/proc"
    >>| Array.to_list
    >>= IO.List.filter_map ~f:(fun pid ->
      (* Failures usually aren't a fatal *system* condition. procfs queries on Linux
         simply are not consistent. They're generally thwarted by terminating processes.
         We simply skip the proc entry on failure.
      *)
      match Option.try_with (fun () -> Pid.of_string pid) with
      | None -> return None
      | Some pid -> Process.load ?load_tasks pid >>| Or_error.ok)
  ;;

  let get_pid_ancestry_unsafe ?load_tasks pid =
    let rec get_pid_branch branch pid =
      match%bind Process.load ?load_tasks pid with
      | Ok process ->
        let new_branch = process :: branch in
        (match Process.Stat.ppid process.stat with
         | None -> return (Or_error.return new_branch)
         | Some ppid -> get_pid_branch new_branch ppid)
      | Error _ as error -> return error
    in
    match%map get_pid_branch [] pid with
    | Ok branch -> List.rev branch
    | Error e -> failwithf "Error collecting process tree: %s" (Error.to_string_hum e) ()
  ;;

  let with_pid_exn ?load_tasks pid = Process.load ?load_tasks pid >>| Or_error.ok_exn
  let with_pid ?load_tasks pid = Process.load ?load_tasks pid >>| Or_error.ok

  (* we just do a normal pid lookup--perhaps there's a reason to avoid that? we could
     explicitly load /proc/self. *)
  let self ?load_tasks () = with_pid_exn ?load_tasks (Core_unix.getpid ())

  let with_uid ?load_tasks uid =
    get_all_procs ?load_tasks ()
    >>| List.filter ~f:(fun p -> Process.Status.uid (Process.status p) = uid)
  ;;

  let with_username_or_error ?load_tasks name =
    match%bind IO.or_error_try_with (fun () -> IO.unix_passwd_getbyname_exn name) with
    | Error _ as error -> return error
    | Ok uid -> with_uid ?load_tasks uid.Unix.Passwd.uid >>| Or_error.return
  ;;

  let with_username_exn ?load_tasks name =
    with_username_or_error ?load_tasks name >>| Or_error.ok_exn
  ;;

  let with_username ?load_tasks name =
    with_username_or_error ?load_tasks name >>| Or_error.ok
  ;;

  (*=
     * This is a partial translation of
   *   sysinfo.c:init_Hertz_value from procps (top)
  *)
  let jiffies_per_second_exn () =
    let rec sample () =
      let%bind up1 = get_uptime () in
      let%bind statlines = IO.read_lines "/proc/stat" in
      let%bind up2 = get_uptime () in
      (* On modern systems the second line is always cpu0 (even uni-processors) *)
      let statline = Option.value_exn (List.nth statlines 1) in
      let user_j, nice_j, sys_j, idle_j, iowait_j =
        Scanf.sscanf statline "cpu0 %Lu %Lu %Lu %Lu %Lu" (fun a b c d e -> a, b, c, d, e)
      in
      if up2 -. up1 >. 0.01
      then sample () (* sampling latency too high. try again *)
      else (
        let ( + ) = Int64.( + ) in
        return (user_j + nice_j + sys_j + idle_j + iowait_j, (up1 +. up2) /. 2.))
    in
    let%map jiffies, seconds = sample () in
    Int64.to_float jiffies /. seconds
  ;;

  let jiffies_per_second () = IO.option_try_with jiffies_per_second_exn

  let process_age' ~jiffies_per_second p =
    process_age ~start_time:p.Process.stat.Process.Stat.starttime ~jiffies_per_second
  ;;

  let process_age p =
    match%bind jiffies_per_second () with
    | None -> return None
    | Some jiffies_per_second -> process_age' ~jiffies_per_second p >>| Option.some
  ;;

  let meminfo_exn = Meminfo.load_exn
  let meminfo () = IO.option_try_with meminfo_exn
  let loadavg_exn = Loadavg.load_exn
  let loadavg () = IO.option_try_with loadavg_exn
  let pgrep ?load_tasks f = get_all_procs ?load_tasks () >>= IO.List.filter ~f

  let pkill ~signal f =
    get_all_procs ()
    >>= IO.List.filter_map ~f:(fun p ->
      let%bind result = f p in
      if not result
      then return None
      else (
        let pid = Process.pid p in
        let%map result =
          IO.try_with_handler
            ~here:[%here]
            ~f:(fun () ->
              return
                (Ok
                   (ignore
                      (Signal_unix.send signal (`Pid pid) : [ `No_such_process | `Ok ]))))
            ~handler:(function
              | Unix.Unix_error (e, _, _) -> Error e
              | e ->
                Exn.reraisef
                  e
                  "Procfs.pkill caught exception trying to signal process %s"
                  (Pid.to_string pid)
                  ())
        in
        Some (pid, result)))
    >>| List.rev
  ;;

  let uptime () = get_uptime () >>| Time_ns.Span.of_sec
  let mounts () = IO.read_lines "/proc/mounts" >>| List.map ~f:Mount.of_string

  let diskstats_exn () =
    IO.read_lines "/proc/diskstats" >>| List.map ~f:Diskstat.of_string
  ;;

  let diskstats () = IO.option_try_with diskstats_exn

  let mounts_of_fstab () =
    IO.read_lines "/etc/fstab"
    >>| (* strip comments *)
    List.map ~f:(fun line ->
      (* filter '#' *)
      match String.split ~on:'#' line with
      | [] -> ""
      | content :: _comment -> content)
    (* turn tabs into spaces *)
    >>| List.map ~f:(String.tr ~target:'\t' ~replacement:' ')
    (* chop padding *)
    >>| List.map ~f:String.strip
    >>| List.filter ~f:(Fn.non String.is_empty)
    >>| List.map ~f:Mount.of_string
  ;;

  let supported_filesystems () =
    IO.read_lines "/proc/filesystems"
    >>| List.map ~f:(fun line ->
      match String.split ~on:'\t' line |> List.rev with
      | vfstype :: _ -> vfstype
      | _ -> failwithf "Procfs.supported_filesystems: bad format: %s" line ())
  ;;

  module Pagemap = struct
    type t = file_descr

    let present_flag = Int64.(1L lsl 63)
    let swapped_flag = Int64.(1L lsl 62)
    let page_type_flag = Int64.(1L lsl 61)
    let exclusive_map_flag = Int64.(1L lsl 56)
    let soft_dirty_flag = Int64.(1L lsl 55)
    let swap_offset_flag = Int64.(bit_not 0L lsr 10)
    let swap_type_flag = Int64.(bit_not 0L lsr 60)
    let pfn_flag = swap_offset_flag
    let page_size = Int64.of_int (Mmap.get_page_size_in_bytes ())
    let page_entry_size = 8L

    module Page_table_entry = struct
      module Page_type = struct
        type t =
          | File_page
          | Shared_anon
        [@@deriving sexp_of]
      end

      type t =
        { pfn : int64 option
        ; swap_type : char option
        ; swap_offset : int64 option
        ; soft_dirty : bool
        ; exclusive_map : bool
        ; page_type : Page_type.t
        ; swapped : bool
        ; present : bool
        }
      [@@deriving sexp_of]
    end

    let create reader = reader

    let open_map ~pid =
      let filename = [%string "/proc/%{pid#Pid}/pagemap"] in
      IO.open_file_readonly filename
    ;;

    let get_pte =
      let buf = Bytes.create (Int.of_int64_trunc page_entry_size) in
      fun t ~virt ->
        let open Int64 in
        let pos = virt / page_size * page_entry_size in
        (* lseek to the correct offset in the file *)
        let%bind offset_bytes = IO.lseek_set t pos in
        (* Check error case *)
        if offset_bytes = pos - 1L
        then
          return
            (Or_error.error_s
               [%message
                 "Virtual address invalid: not within pagemap" (virt : Int64.Hex.t)])
        else (
          let%map bytes_read = IO.read t ~len:(Int.of_int64_trunc page_entry_size) ~buf in
          if Int.to_int64 bytes_read < page_entry_size
          then
            Or_error.error_s
              [%message
                "virtual address invalid: not within pagemap" (virt : Int64.Hex.t)]
          else Ok (Bytes.unsafe_get_int64 buf 0))
    ;;

    let close t = IO.close t

    let with_pagemap ~pid ~f =
      let%bind pagemap = open_map ~pid in
      IO.protect ~f:(fun () -> f pagemap) ~finally:(fun () -> close pagemap)
    ;;

    (*=Converts a page table entry into a record with all of its components, described in
       https://www.kernel.org/doc/Documentation/vm/pagemap.txt

       - Bits 0-54  page frame number (PFN) if present
       - Bits 0-4   swap type if swapped
       - Bits 5-54  swap offset if swapped
       - Bit  55    pte is soft-dirty (see Documentation/vm/soft-dirty.txt)
       - Bit  56    page exclusively mapped (since 4.2)
       - Bits 57-60 zero
       - Bit  61    page is file-page or shared-anon (since 3.5)
       - Bit  62    page swapped
       - Bit  63    page present *)
    let get_pte_record t ~virt : Page_table_entry.t Or_error.t IO.io =
      let%map pte = get_pte t ~virt in
      Or_error.map pte ~f:(fun pte ->
        let open Int64 in
        let is_bit_set pte flag = bit_and pte flag <> 0L in
        let present = is_bit_set pte present_flag in
        let swapped = is_bit_set pte swapped_flag in
        let page_type =
          if is_bit_set pte page_type_flag
          then Page_table_entry.Page_type.File_page
          else Page_table_entry.Page_type.Shared_anon
        in
        let exclusive_map = is_bit_set pte exclusive_map_flag in
        let soft_dirty = is_bit_set pte soft_dirty_flag in
        let swap_offset =
          if swapped then Some (bit_and pte swap_offset_flag lsr 5) else None
        in
        (* Using Char.of_int_exn as the value given as input will always have only 4 bits. *)
        let swap_type =
          if swapped
          then Some (Char.of_int_exn (to_int_trunc (bit_and pte swap_type_flag)))
          else None
        in
        let pfn = if present then Some (bit_and pte pfn_flag) else None in
        ({ pfn
         ; swap_type
         ; swap_offset
         ; soft_dirty
         ; exclusive_map
         ; page_type
         ; swapped
         ; present
         }
         : Page_table_entry.t))
    ;;

    let get_phys_addr t ~virt =
      let%map pte_record = get_pte_record t ~virt in
      Or_error.map pte_record ~f:(fun pte_record ->
        let open Int64 in
        let pfn = Option.value_exn pte_record.pfn in
        let page_addr = Int64.round_down virt ~to_multiple_of:page_size in
        (pfn * page_size) + (virt - page_addr))
    ;;

    (* Converts the virtual address to physical by reading the given process's pagemap. *)
    let virt_to_pte_record ~virt ~pid =
      with_pagemap ~pid ~f:(fun pagemap -> get_pte_record pagemap ~virt)
    ;;

    module For_testing = struct
      let get_pte = get_pte
    end
  end

  module Device_number = struct
    type t =
      { major : int
      ; minor : int
      }
    [@@deriving equal ~localize, sexp_of]
  end

  module Lock = struct
    module Mechanism = struct
      type file_region =
        { start : int
        ; end_ : [ `At of int | `Eof ]
        }
      [@@deriving equal ~localize, sexp_of]

      type t =
        | Flock of Pid.t option
        | Ofd of file_region
        | Posix of Pid.t option * file_region
      [@@deriving equal ~localize, sexp_of]
    end

    type t =
      { mechanism : Mechanism.t
      ; type_ : [ `Read | `Write ]
      ; inode : (Device_number.t * Process.Inode.t) option
      }
    [@@deriving equal ~localize, sexp_of]
  end

  (* To follow the parsing logic here, see [locks_show] in fs/locks.c:
     - https://github.com/torvalds/linux/blob/v4.18/fs/locks.c
     - https://github.com/torvalds/linux/blob/v6.1/fs/locks.c

     Mandatory locks are removed in 6.1, and on the assumption we aren't using them and
     won't be prior to finishing the upgrade of our systems, we filter them out. *)
  let parse_locks =
    List.filter_map ~f:(fun line ->
      try
        match String.split line ~on:' ' |> List.filter ~f:(Fn.non String.is_empty) with
        | _lock_index :: "->" :: _ ->
          (* This is a request for a lock, not an active lock. *)
          None
        | [ lock_index (* Not necessarily ordered or contiguous *)
          ; mechanism
          ; mode
          ; type_
          ; pid
          ; inode_info
          ; region_start
          ; region_end
          ] ->
          let () = Scanf.sscanf lock_index "%i:%!" (ignore : int -> unit) in
          let%bind.Option (mechanism : Lock.Mechanism.t) =
            let%bind.Option () =
              match mode with
              | "ADVISORY" | "*NOINODE*" -> Some ()
              | "MANDATORY" | "MSNFS" ->
                (* After all our systems are upgraded to Linux 6.1, which does not have
                   mandatory locks, we can remove this case. *)
                None
              | "ACTIVE" | "BREAKER" | "BREAKING" ->
                (* Lease support is not currently implemented. *)
                None
              | "UNKNOWN" -> None
              | _ -> failwithf "Unexpected lock mode: %s" mode ()
            in
            let region_start = Int.of_string region_start in
            let region_end =
              match region_end with
              | "EOF" -> `Eof
              | _ -> `At (Int.of_string region_end)
            in
            match mechanism with
            | "ACCESS" ->
              (* Documentation says, "not trying to lock, just looking"
                 https://github.com/torvalds/linux/blob/v6.1/include/linux/fs.h#L1009 *)
              None
            | "POSIX" ->
              let pid = Option.try_with (fun () -> Pid.of_string pid) in
              Some
                (Lock.Mechanism.Posix (pid, { start = region_start; end_ = region_end }))
            | "OFDLCK" ->
              assert (String.equal pid "-1");
              Some (Ofd { start = region_start; end_ = region_end })
            | "FLOCK" ->
              let pid = Option.try_with (fun () -> Pid.of_string pid) in
              assert (Int.equal region_start 0);
              assert ([%equal: [ `At of int | `Eof ]] region_end `Eof);
              Some (Flock pid)
            | "LEASE" | "DELEG" ->
              (* Lease support is not currently implemented. *)
              None
            | "UNKNOWN" -> None
            | _ -> failwithf "Unexpected lock mechanism: %s" mechanism ()
          in
          let%map.Option type_ =
            match type_ with
            | "READ" -> Some `Read
            | "WRITE" -> Some `Write
            | "UNLCK" -> None (* Transient. *)
            | _ ->
              (* The types "RW" and "NONE" may appear for mandatory locks on 4.18, but we
                 filter out mandatory locks above. *)
              failwithf "Unexpected lock type: %s" type_ ()
          in
          let inode =
            match inode_info with
            | "<none>:0" -> None
            | _ ->
              Scanf.sscanf inode_info "%x:%x:%Lu%!" (fun major minor inode ->
                let inode = Process.Inode.of_int64 inode in
                let device = { Device_number.major; minor } in
                Some (device, inode))
          in
          { Lock.mechanism; type_; inode }
        | _ -> failwith "Unexpected number of fields"
      with
      | exn -> raise_s [%message "Failed to parse line in /proc/locks" line (exn : exn)])
  ;;

  let get_locks () = IO.read_lines "/proc/locks" >>| parse_locks

  let get_pids_holding_flock path =
    let%map { st_dev; st_ino; _ } = IO.stat (File_path.to_string path)
    and locks = get_locks () in
    let target_inode = Process.Inode.of_int st_ino in
    List.filter_map locks ~f:(fun { mechanism; type_ = _; inode } ->
      match mechanism, inode with
      | Flock pid, Some (device, inode) when Process.Inode.equal inode target_inode ->
        let%bind.Option pid in
        let%tydi { major; minor } = device in
        Option.some_if (equal st_dev (Core_unix.makedev ~major ~minor)) pid
      | _ -> None)
  ;;

  module For_testing = struct
    let parse_locks = parse_locks
  end
end

(* In_channel.input_all creates a 64k buffer and string every time. Also, In_channel.t's
   are custom blocks with finalizers that are allocated on the major heap. get_all_procs
   calls this many, many times and causes terrible GC performance. This un-thread-safe
   version is a work-around. *)
let input_all_with_reused_buffer () =
  let buf_size = 65536 in
  let buf = Bytes.create buf_size in
  let buffer = Buffer.create buf_size in
  let read_all fd =
    let rec loop () =
      let len = Unix.read fd ~buf ~len:(Bytes.length buf) in
      if len > 0
      then (
        Buffer.add_subbytes buffer buf ~pos:0 ~len;
        loop ())
    in
    loop ();
    let res = Buffer.contents buffer in
    Buffer.clear buffer;
    res
  in
  let input_all fn = Unix.with_file fn ~mode:[ Unix.O_RDONLY ] ~f:read_all in
  stage input_all
;;

module Blocking_IO = struct
  type 'a io = 'a
  type file_descr = Unix.File_descr.t

  let read_lines = In_channel.read_lines ~fix_win_eol:true
  let readdir = Sys_unix.readdir
  let readlink = Unix.readlink
  let string_of_file = unstage (input_all_with_reused_buffer ())
  let unix_passwd_getbyname_exn = Unix.Passwd.getbyname_exn
  let open_file_readonly filename = Unix.openfile ~mode:[ O_RDONLY ] filename
  let lseek_set file pos = Unix.lseek file pos ~mode:SEEK_SET
  let close file = Unix.close file
  let read ~len file ~buf = Unix.read ~len file ~buf
  let protect ~f ~finally = protect ~f ~finally
  let stat = Unix.stat

  module Monad = Monad.Ident
  module List = List

  (* We ignore [here]. This function should show up in the backtrace as normal. This means
     the function will ignore being passed a location that's not [%here], but we can't do
     anything about that, I can't find any functions for manually adding to a backtrace.
  *)
  let try_with_handler ~here:(_ : Source_code_position.t) ~f ~handler =
    try f () with
    | exn -> handler exn
  ;;

  let option_try_with = Option.try_with
  let or_error_try_with f = Or_error.try_with f
end

module Blocking = Make (Blocking_IO)
include Blocking
