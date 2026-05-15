open! Core
module Unix := Core_unix
module Ipproto = Procfs.Net.Ipproto
module Inet_addr = Unix.Inet_addr

val bind_inet
  :  Unix.File_descr.t
  -> address:Inet_addr.t
  -> port_low:int
  -> port_high:int
  -> int option

module Make_socket_test (M : sig
    type state [@@deriving sexp_of]

    val socket_domain : Unix.socket_domain
    val socket_type : Unix.socket_type
    val protocol : Ipproto.t
    val socket_postcall : Unix.File_descr.t -> unit
    val bind_postcall : Unix.File_descr.t -> unit
    val load_exn : unit -> state Procfs.Net.t list
  end) : sig
  val run_test : unit -> unit
end
