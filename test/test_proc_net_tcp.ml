open Core
module Unix = Core_unix
module Tcp = Procfs.Net.Tcp
module Tcp_state = Procfs.Net.Tcp_state
module Ipproto = Procfs.Net.Ipproto

module Tcp_test = Test_proc_net.Make_socket_test (struct
    type state = Tcp_state.t [@@deriving sexp_of]

    let socket_domain = Unix.PF_INET
    let socket_type = Unix.SOCK_STREAM
    let protocol = Ipproto.TCP
    let socket_postcall fd = Unix.setsockopt fd Unix.SO_REUSEADDR true
    let bind_postcall fd = Unix.listen fd ~backlog:1
    let load_exn = Tcp.load_exn
  end)

let%expect_test "tcp state" =
  Tcp_test.run_test ();
  (* Note that unlike UDP sockets, [bind] doesn't make a TCP socket show up in /proc -- it
     doesn't show up there until you do [listen] (or, presumably, [connect]) *)
  [%expect
    {|
    ("after bind" (our_socket ()))
    ("after bind postcall" (our_socket.local_address 127.0.0.1)
     (our_socket.remote_address 0.0.0.0) (our_socket.remote_port ())
     (our_socket.state TCP_LISTEN))
    ("after close" (our_socket ()))
    |}]
;;
