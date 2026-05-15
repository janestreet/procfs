open Core
module Unix = Core_unix
module Udp = Procfs.Net.Udp
module Udp_state = Procfs.Net.Udp_state
module Ipproto = Procfs.Net.Ipproto
module Inet_addr = Unix.Inet_addr

module Udp_test = Test_proc_net.Make_socket_test (struct
    type state = Udp_state.t [@@deriving sexp_of]

    let socket_domain = Unix.PF_INET
    let socket_type = Unix.SOCK_DGRAM
    let protocol = Ipproto.UDP
    let socket_postcall = Fn.ignore

    let bind_postcall fd =
      Unix.connect fd ~addr:(Unix.ADDR_INET (Inet_addr.localhost, 12345))
    ;;

    let load_exn = Udp.load_exn
  end)

let%expect_test "udp state" =
  Udp_test.run_test ();
  [%expect
    {|
    ("after bind" (our_socket.local_address 127.0.0.1)
     (our_socket.remote_address 0.0.0.0) (our_socket.remote_port ())
     (our_socket.state No_default_destination_assigned))
    ("after bind postcall" (our_socket.local_address 127.0.0.1)
     (our_socket.remote_address 127.0.0.1) (our_socket.remote_port (12345))
     (our_socket.state Default_destination_assigned))
    ("after close" (our_socket ()))
    |}]
;;
