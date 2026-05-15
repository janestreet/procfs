open! Core

(* allow procfs_async to include the interface *)
module Procfs_intf = Procfs_intf

module Blocking_IO :
  Procfs_intf.IO with type 'a io := 'a and type file_descr = Core_unix.File_descr.t

module Make (IO : Procfs_intf.IO) :
  Procfs_intf.S with type 'a io := 'a IO.io and type file_descr = IO.file_descr

include Procfs_intf.S with type 'a io := 'a and type file_descr = Core_unix.File_descr.t

(* jlau: For Network and some other stuffs, we do not include in the async interface yet *)

val input_all_with_reused_buffer : unit -> (string -> string) Staged.t
