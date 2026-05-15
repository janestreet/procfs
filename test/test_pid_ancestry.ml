open Core

let%expect_test "Process.get_pid_ancestry_unsafe returns at least 2 processes" =
  (match Procfs.get_pid_ancestry_unsafe (Core_unix.getpid ()) with
   | myself :: parent :: _rest ->
     if Pid.( <> ) (Procfs.Process.pid myself) (Core_unix.getpid ())
     then print_endline "If I'm not myself, who am I?"
     else if Pid.( <> )
               (Procfs.Process.stat myself |> Procfs.Process.Stat.ppid |> Option.value_exn)
               (Procfs.Process.pid parent)
     then print_endline "Who's my parent?"
     else print_endline "At least 2 processes including me and my parent"
   | _ -> print_endline "singleton or none");
  [%expect {| At least 2 processes including me and my parent |}]
;;
