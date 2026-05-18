open! Core
module Unix = Core_unix

module type IO = sig
  type 'a io
  type file_descr

  module Monad : sig
    include Monad.S with type 'a t := 'a io
  end

  (* These could all be defined with the monad interface, but it's easier and may be more
     efficient to include them here as well. *)
  module List : sig
    val filter : 'a list -> f:('a -> bool io) -> 'a list io
    val filter_map : 'a list -> f:('a -> 'b option io) -> 'b list io
    val map : 'a list -> f:('a -> 'b io) -> 'b list io
  end

  (* Some functions in procfs lib would call some library functions, and handle only some
     of the exceptions and then throw others. To make the exception looks better (with a
     better source code location info in the exception message) in Async, we have this
     try_with_handler function, which, in Blocking_IO it just do try/with , and in
     Async_IO we wrap it with monitor.

     And ~here option would be ignored in Blocking_IO because the exception in non-async
     environment already have good source code location.
  *)

  val try_with_handler
    :  here:Source_code_position.t
    -> f:(unit -> 'a io)
    -> handler:(exn -> 'a)
    -> 'a io

  val option_try_with : (unit -> 'a io) -> 'a option io
  val or_error_try_with : (unit -> 'a io) -> 'a Or_error.t io
  val read_lines : string -> string list io
  val readdir : string -> string array io
  val readlink : string -> string io
  val string_of_file : string -> string io
  val unix_passwd_getbyname_exn : string -> Unix.Passwd.t io
  val open_file_readonly : string -> file_descr io
  val lseek_set : file_descr -> int64 -> int64 io
  val close : file_descr -> unit io
  val read : len:int -> file_descr -> buf:bytes -> int io
  val protect : f:(unit -> 'a io) -> finally:(unit -> unit io) -> 'a io
  val stat : string -> Unix.stats io
end

(** Process and system stats *)
module type S = sig
  type 'a io
  type file_descr
  type bigint = Big_int.big_int [@@deriving sexp_of]

  module Process : sig
    module Inode : sig
      type t [@@deriving sexp_of]

      val of_string : string -> t
      val to_string : t -> string
      val of_int64 : int64 -> t
      val to_int64 : t -> int64

      include Comparable.S_plain with type t := t
      include Hashable.S_plain with type t := t
    end

    module Limits : sig
      module Rlimit : sig
        type value =
          [ `unlimited
          | `limited of bigint
          ]
        [@@deriving sexp_of]

        type t =
          { soft : value
          ; hard : value
          }
        [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]
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
      [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

      val of_string : string -> t
    end

    module Maps : sig
      module Permissions : sig
        type t = private Int63.t

        val read : t
        val write : t
        val execute : t
        val private_ : t

        include Flags.S with type t := t

        val of_string : string -> t
      end

      module Entry : sig
        type t =
          { start_addr : Int64.Hex.t
          ; end_addr : Int64.Hex.t
          ; permissions : Permissions.t
          ; label : string option
          ; offset : Int64.Hex.t
          }
        [@@deriving sexp_of]
      end

      type t = Entry.t list [@@deriving sexp_of]

      val of_lines : string list -> t
    end

    module Stat : sig
      module State : sig
        (** Mapping of states taken from output of [man proc] on EL8. *)
        type t =
          | Running
          | Interruptible_sleep
          | Uninterruptible_disk_sleep
          | Zombie
          | Stopped (* Before Linux 2.6.33 this also included [Tracing_stop] *)
          | Tracing_stop (* Linux 2.6.33 onward. *)
          | Dead (* An internal state we do not expect to see. *)
          | Unknown of char
        [@@deriving equal ~localize, sexp_of]
      end

      type t =
        { comm : string (** The filename of the executable *)
        ; state : State.t
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
        ; signal : bigint (** The bitmap of pending signals. *)
        ; blocked : bigint (** The bitmap of blocked signals. *)
        ; sigignore : bigint (** The bitmap of ignored signals. *)
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
      [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

      (* For a stat string such as "14574 (cat) R 10615 14574 ...", extract_command
         returns (`command "cat", `rest "R 10615 14574 ..."). Note that the pid at the
         beginning is dropped. *)

      val load : Pid.t -> t Or_error.t io
      val process_age : t -> jiffies_per_second:float -> Time_ns.Span.t io
      val extract_command : string -> [ `command of string ] * [ `rest of string ]
      val of_string : string -> t
    end

    module Statm : sig
      type t =
        { size : bigint (** total program size *)
        ; resident : bigint (** resident set size *)
        ; share : bigint (** shared pages *)
        ; text : bigint (** text (code) *)
        ; lib : bigint (** library *)
        ; data : bigint (** data/stack *)
        ; dt : bigint (** dirty pages (unused) *)
        }
      [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

      val of_string : string -> t
    end

    module Status : sig
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
      [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

      val of_string : string -> t
    end

    module Fd : sig
      (* see OpenOnload sources: src/driver/linux_onload/onloadfs.c *)
      module Onload : sig
        module Socket_id : sig
          (** host-wide identification of an Onload socket *)
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
      [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]
    end

    module Cmdline : sig
      (** Cmdline is a null-delimited string, read from the process-owned memory. This
          means the process can overwrite that with anything they want, so it's not
          completely reliable. *)
      type t [@@deriving sexp_of]

      (** The raw string is null-separated, with an extra null terminator. It's empty for
          many system processes. *)
      val to_raw_string : t -> string

      (** A shortcut for [Sys.concat_quoted (parse_or_empty t)]. *)
      val to_shell_string : t -> string

      (** The command is often unavailable, for example for a bunch of system processes.
          In that case an empty list is returned.

          Some processes like to change their command line (for example after they fork),
          in which case they pad the command line with nulls, so you end up getting lots
          of trailing empty strings. *)
      val parse_or_empty : t -> string list
    end

    type t =
      { pid : Pid.t (** Process ID *)
      ; cmdline : Cmdline.t (** Command-line (not reliable). *)
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
      ; oom_adj : int (** OOM killer niceness [range: -17 to +15] *)
      ; oom_score : int (** OOM "sacrifice" priority *)
      }
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]
  end

  module Meminfo : sig
    (** [t] corresponds to the values in /proc/meminfo. All values in bytes, except for
        the hugepages_* numbers which are in hugepagesize count. *)
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
      ; (* New field in CentOS 7 *)
        mem_available : bigint option
      ; hugepages_total : bigint
      ; hugepages_free : bigint
      ; hugepages_rsvd : bigint
      ; hugepages_surp : bigint
      ; hugepagesize : bigint
      ; sreclaimable : bigint
      }
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

    val mem_available : t -> bigint
  end

  module Kstat : sig
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

    val load_exn : unit -> t list io
  end

  module Loadavg : sig
    (** [t] corresponds to the values in /proc/loadavg. *)
    type t =
      { one : float
      ; five : float
      ; fifteen : float
      }
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]
  end

  module Net : sig
    (* will put in some stuff from proc net *)
    module Dev : sig
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

      val interfaces : unit -> string list io
      val of_string : string -> t option
    end

    module Route : sig
      (** See /usr/include/net/route.h and net/ipv4/fib_trie.c in the kernel. Comments
          here are copied from one of those sources. *)
      module Flags : sig
        type t : immutable_data

        include Flags.S with type t := t

        (** Route usable. *)
        val up : t

        (** Destination is a gateway. *)
        val gateway : t

        (** Host entry (net otherwise). *)
        val host : t

        (** Reinstate route after timeout. *)
        val reinstate : t

        (** Created dyn. (by redirect). *)
        val dynamic : t

        (** Modified dyn. (by redirect). *)
        val modified : t

        (** Specific MTU for this route. *)
        val mtu : t

        (** Per route window clamping. *)
        val window : t

        (** Initial round trip time. *)
        val irtt : t

        (** Reject route. *)
        val reject : t

        (** Manually injected route. *)
        val static : t

        (** External resolver. *)
        val xresolve : t

        (** Forwarding inhibited. *)
        val noforward : t

        (** Go to next class. *)
        val throw : t

        (** Do not send packets with DF. *)
        val nopmtudisc : t
      end

      type t =
        { iface : string (* maybe this shouldn't be a string? *)
        ; destination : Unix.Inet_addr.t
        ; gateway : Unix.Inet_addr.t
        ; flags : Flags.t (* [refcnt] and [use] seems to be statically output as zero *)
        ; refcnt : int
        ; use : int
        ; metric : int
        ; mask : Unix.Inet_addr.t
        ; mtu : int
        ; window : int
        ; irtt : int
        }
      [@@deriving sexp_of, fields ~getters] [@@fields.no_zero_alloc]

      val load_exn : unit -> t list io
      val default : unit -> Unix.Inet_addr.t io
    end

    module Ipproto : sig
      (* as per /usr/include/netinet/in.h; there might be a better place for this to exist *)

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
      [@@deriving sexp_of, compare ~localize, equal ~localize, hash]

      val to_int : t -> int
      val of_int : int -> t
      val to_string : t -> string

      module Stable : sig
        module V1 : Stable_without_comparator with type t = t
      end
    end

    (* This should probably be somewhere else but I don't know where. *)
    module Tcp_state : sig
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

      val to_int : t -> int
      val of_int : int -> t
    end

    module Udp_state : sig
      (** This is our best guess at the current meanings of these state codes based on
          observations of /proc/net/udp and readings of the netstat / linux kernel source
          code.

          [Default_destination_assigned] state refers to UDP sockets where somebody has
          executed a [connect] syscall, this is from "man socket":

          If the socket sockfd is of type SOCK_DGRAM then addr is the address to which
          datagrams are sent by default, and the only address from which datagrams are
          received. *)
      type t =
        | Default_destination_assigned
        | No_default_destination_assigned
        | Unknown of int
      [@@deriving sexp_of, equal ~localize]

      val to_int : t -> int
      val of_int : int -> t
    end

    module Raw_state : sig
      (* Raw socket currently shares the same connection code with udp in Linux kernel so
         it can have 01 in the state if it is "connected" (ie. default destination
         assigned) *)

      type t =
        | Default_destination_assigned
        | No_default_destination_assigned
        | Unknown of int
      [@@deriving sexp_of, equal ~localize]

      val to_int : t -> int
      val of_int : int -> t
    end

    module Socket_state : sig
      type t =
        | Tcp of Tcp_state.t
        | Udp of Udp_state.t
        | Raw of Raw_state.t
      [@@deriving sexp_of, equal ~localize]
    end

    type 'state t =
      { sl : int
      ; local_address : Core_unix.Inet_addr.t
      ; local_port : int
      ; remote_address : Core_unix.Inet_addr.t
      ; (* can be [None] if there's no connection. *)
        remote_port : int option
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
    [@@deriving sexp_of, fields ~getters] [@@fields.no_zero_alloc]

    val map_state : 'a t -> f:('a -> 'b) -> 'b t

    (** /proc/net/[{tcp,udp,raw}][{,6}], or what netstat or lsof -i parses. *)
    module type Inet_l4_proto = sig
      type state
      type nonrec t = state t [@@deriving sexp_of]

      val socket_domain : Unix.socket_domain
      val ipproto : Ipproto.t
      val of_line : string -> t option
      val of_line_exn : string -> t
      val load_exn : unit -> t list io
    end

    module Tcp : Inet_l4_proto with type state := Tcp_state.t
    module Udp : Inet_l4_proto with type state := Udp_state.t
    module Raw : Inet_l4_proto with type state := Raw_state.t
    module Tcp6 : Inet_l4_proto with type state := Tcp_state.t
    module Udp6 : Inet_l4_proto with type state := Udp_state.t
    module Raw6 : Inet_l4_proto with type state := Raw_state.t

    module Arp : sig
      module Hardware_type : sig
        (* see /usr/include/linux/if_arp.h *)

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

        val to_int : t -> int
        val of_int : int -> t
      end

      module Flags : sig
        type t : immutable_data [@@deriving sexp_of]

        include Flags.S with type t := t

        (* for the meaning of these flags, please check:

           man 7 arp

           /usr/include/net/if_arp.h /usr/include/linux/if_arp.h
        *)

        val lookup_complete : t
        val permanent_entry : t
        val publish_entry : t
        val trailers_requested : t
        val use_a_netmask : t
        val do_not_answer : t
      end

      type t =
        { ip_address : Unix.Inet_addr.t
        ; hw_type : Hardware_type.t
        ; flags : Flags.t
        ; hw_address : Mac_address.t
            (* since kernel statically prints * for mask (between [hw_address] and
               [device]), we don't expose mask field here *)
        ; device : string
        }
      [@@deriving sexp_of]

      val load_exn : unit -> t list io
    end

    module Igmp : sig
      type t =
        { (* for the meaning of these fields, see kernel source at net/ipv4/igmp.c
             (function [igmp_mc_seq_show]) *)
          idx : int
        ; device : string
        ; querier : int option
        ; group : Unix.Inet_addr.t
        ; users : int
        ; timer_running : bool
        ; timer : int
        ; reporter : int
        }
      [@@deriving sexp_of]

      val load_exn : unit -> t list io
    end

    module Mca_flags : sig
      (* this is the value assigned to [mca_flags] inside [struct ifmcaddr6] (see kernel
         source at include/net/if_inet6.h) and described as

         # define MAF_TIMER_RUNNING 0x01 ...
      *)

      type t : immutable_data [@@deriving sexp_of]

      include Flags.S with type t := t

      val timer_running : t
      val last_reporter : t
      val loaded : t
      val noreport : t
      val gsquery : t
    end

    module Igmp6 : sig
      type t =
        { (* for the meaning of these fields, see kernel source at net/ipv6/mcast.c
             (function [igmp6_mc_seq_show]) *)
          idx : int
        ; device : string
        ; group : Unix.Inet_addr.t
        ; users : int
        ; flags : Mca_flags.t
        ; timer : int
        }
      [@@deriving sexp_of]

      val load_exn : unit -> t list io
    end
  end

  module Mount : sig
    type t =
      { spec : string (* block device special name *)
      ; file : string (* fs path prefix *)
      ; vfstype : string (* ext3, nfs, etc. *)
      ; mntops : string list (* mount options -o *)
      ; freq : int (* dump frequency *)
      ; (* pass number of parallel dump *)
        passno : int
      }
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]
  end

  module Diskstat : sig
    (* NOTE: see the kernel docs for more details of these fields:
       https://www.kernel.org/doc/Documentation/admin-guide/iostats.rst

       discards appeared in 4.18+, flushes in 5.5+.
    *)
    type t =
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
    [@@deriving fields ~getters, sexp_of] [@@fields.no_zero_alloc]

    module Stable : sig
      module V1 : Stable_without_comparator with type t = t
    end
  end

  val mounts : unit -> Mount.t list io
  val mounts_of_fstab : unit -> Mount.t list io
  val supported_filesystems : unit -> string list io

  (** Options when returning process details: [load_tasks] (default [true]) indicates that
      individual task (thread) info should be loaded into [task_stats]. *)
  type 'a with_process_load_args = ?load_tasks:bool -> 'a

  (** [get_all_procs] returns a list of all processes on the system. *)
  val get_all_procs : (unit -> Process.t list io) with_process_load_args

  (** [get_pid_ancestry_unsafe] returns a list of processes, with the given PID at the
      head following parents to the tail (typically the init task). This is inherently
      racey, as a process could reparent (or seemingly reparent) mid-walk. *)
  val get_pid_ancestry_unsafe : (Pid.t -> Process.t list io) with_process_load_args

  val self : (unit -> Process.t io) with_process_load_args

  (** [with_pid] returns a single process that matches the given pid. If there is no such
      process, [with_pid] returns [None]. *)
  val with_pid : (Pid.t -> Process.t option io) with_process_load_args

  (** [with_pid_exn] is like [with_pid], except it raises [Not_found] instead of returning
      [None]. *)
  val with_pid_exn : (Pid.t -> Process.t io) with_process_load_args

  (** [with_uid uid] returns all processes owned by uid. *)
  val with_uid : (int -> Process.t list io) with_process_load_args

  (** [pgrep f] returns all processes for which f is true. *)
  val pgrep : ((Process.t -> bool io) -> Process.t list io) with_process_load_args

  (** [pkill ~signal f] sends the signal to all processes for which f returns true. It
      returns the list of processes that were signaled, and the resulting errors if any. *)
  val pkill
    :  signal:Signal.t
    -> (Process.t -> bool io)
    -> (Pid.t * (unit, Unix.Error.t) Result.t) list io

  (** [with_username] calls with_uid after looking up the user's uid *)
  val with_username : (string -> Process.t list option io) with_process_load_args

  (** [with_username_exn] is like [with_username], except it raises instead of returning
      [None]. *)
  val with_username_exn : (string -> Process.t list io) with_process_load_args

  (** [jiffies_per_second]. A jiffy "is one tick of the system timer interrupt. It is not
      an absolute time interval unit, since its duration depends on the clock interrupt
      frequency of the particular hardware platform."

      Further reading: https://en.wikipedia.org/wiki/Jiffy_(time) *)
  val jiffies_per_second : unit -> float option io

  (** [jiffies_per_second_exn] is like [jiffies_per_second], except it raises instead of
      returning [None]. *)
  val jiffies_per_second_exn : unit -> float io

  (** [meminfo] queries /proc/meminfo and fills out Meminfo.t. All values in bytes. *)
  val meminfo : unit -> Meminfo.t option io

  (** [meminfo_exn] is like [meminfo], except it raises instead of returning [None]. *)
  val meminfo_exn : unit -> Meminfo.t io

  (** [loadavg] parses /proc/loadavg. *)
  val loadavg : unit -> Loadavg.t option io

  (** [loadavg_exn] is like [loadavg], except it raises instead of returning [None]. *)
  val loadavg_exn : unit -> Loadavg.t io

  val uptime : unit -> Time_ns.Span.t io

  (** [diskstats] queries /proc/diskstats and returns a list of Diskstat.t. *)
  val diskstats : unit -> Diskstat.t list option io

  (** [diskstats_exn] is like [diskstats] except it raises instead of returning [None]. *)
  val diskstats_exn : unit -> Diskstat.t list io

  val process_age : Process.t -> Time_ns.Span.t option io
  val process_age' : jiffies_per_second:float -> Process.t -> Time_ns.Span.t io

  module Pagemap : sig
    type t

    (* Structure described in: https://www.kernel.org/doc/Documentation/vm/pagemap.txt *)
    module Page_table_entry : sig
      module Page_type : sig
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

    val create : file_descr -> t

    (* Opens the pagemap for the given process pid. *)
    val open_map : pid:Pid.t -> t io

    (* Closes the pagemap file. *)
    val close : t -> unit io

    (* Opens the pagemap for the given [pid], calls the given function [f] and closes the
       pagemap file once the result of the function gets determined. *)
    val with_pagemap : pid:Pid.t -> f:(t -> 'a io) -> 'a io

    (* Converts the virtual address to its page table entry in virtual memory by reading
       the current process's pagemap. *)
    val virt_to_pte_record : virt:int64 -> pid:Pid.t -> Page_table_entry.t Or_error.t io

    (* Extracts the elements of a page table entry into a record. *)
    val get_pte_record : t -> virt:int64 -> Page_table_entry.t Or_error.t io

    (* Converts the given virtual address and its pte to its physical address. *)
    val get_phys_addr : t -> virt:int64 -> int64 Or_error.t io

    module For_testing : sig
      val get_pte : t -> virt:int64 -> int64 Or_error.t io
    end
  end

  module Device_number : sig
    type t =
      { major : int
      ; minor : int
      }
    [@@deriving equal ~localize, sexp_of]
  end

  module Lock : sig
    module Mechanism : sig
      type file_region =
        { start : int
        ; end_ : [ `At of int | `Eof ]
        }
      [@@deriving equal ~localize, sexp_of]

      type t =
        | Flock of Pid.t option
        | Ofd of file_region (** "Open file description" lock. *)
        | Posix of Pid.t option * file_region
      [@@deriving equal ~localize, sexp_of]
    end

    type t =
      { mechanism : Mechanism.t
      ; type_ : [ `Read | `Write ] (** Read = Shared; Write = Exclusive. *)
      ; inode : (Device_number.t * Process.Inode.t) option
      }
    [@@deriving equal ~localize, sexp_of]
  end

  val get_locks : unit -> Lock.t list io

  (** This is a helper function to get the list of processes holding an advisory
      flock-style lock on a given path. *)
  val get_pids_holding_flock : File_path.t -> Pid.t list io

  module For_testing : sig
    val parse_locks : string list -> Lock.t list
  end
end
