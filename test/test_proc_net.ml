open Core
module Unix = Core_unix
module Ipproto = Procfs.Net.Ipproto
module Inet_addr = Unix.Inet_addr

let rec bind_inet fd ~address ~port_low ~port_high =
  if port_low > port_high
  then None
  else (
    let addr = Unix.ADDR_INET (address, port_low) in
    match Unix.bind fd ~addr with
    | exception Unix.Unix_error (Unix.EADDRINUSE, _, _) ->
      let port_low = port_low + 1 in
      bind_inet fd ~address ~port_low ~port_high
    | () -> Some port_low)
;;

module Make_socket_test (M : sig
    type state [@@deriving sexp_of]

    val socket_domain : Unix.socket_domain
    val socket_type : Unix.socket_type
    val protocol : Ipproto.t
    val socket_postcall : Unix.File_descr.t -> unit
    val bind_postcall : Unix.File_descr.t -> unit
    val load_exn : unit -> state Procfs.Net.t list
  end) =
struct
  let run_test () =
    let address = Inet_addr.localhost
    and port_low = 8192
    and port_high = 65534
    and domain = M.socket_domain
    and kind = M.socket_type
    and protocol = Ipproto.to_int M.protocol in
    let fd = Unix.socket ~domain ~kind ~protocol () in
    M.socket_postcall fd;
    let port = bind_inet fd ~address ~port_low ~port_high in
    match port with
    | None ->
      raise_s
        [%message
          "unable to run any bind in this range"
            (port_low : int)
            (port_high : int)
            (address : Inet_addr.t)]
    | Some port ->
      let print_our_socket msg =
        match
          List.find (M.load_exn ()) ~f:(fun p ->
            Unix.Inet_addr.equal p.local_address address && p.local_port = port)
        with
        | None -> print_s [%message msg ~our_socket:(None : _ option)]
        | Some our_socket ->
          print_s
            [%message
              msg
                (our_socket.local_address : Inet_addr.t)
                (* Note we can't print local port because it won't always be the same. *)
                (our_socket.remote_address : Inet_addr.t)
                (our_socket.remote_port : int option)
                (our_socket.state : M.state)]
      in
      print_our_socket "after bind";
      M.bind_postcall fd;
      print_our_socket "after bind postcall";
      Unix.close fd;
      print_our_socket "after close"
  ;;
end
