open Core
open File_path.Operators
module Unix = Core_unix

let%test_unit "input_all_with_reused_buffer clears partial reads after exceptions" =
  Filesystem_core.within_temp_dir (fun () ->
    let fifo = ?/"partial-read" |> File_path.to_string in
    let clean_file = ?/"clean" |> File_path.to_string in
    Unix.mkfifo fifo ~perm:0o600;
    let input_all = unstage (Procfs.input_all_with_reused_buffer ()) in
    match Unix.fork () with
    | `In_the_child ->
      let fd = Unix.openfile fifo ~mode:[ O_WRONLY ] in
      let bytes_written = Unix.write_substring fd ~buf:"stale" ~pos:0 ~len:5 in
      assert (bytes_written = 5);
      Unix.sleep 3;
      Unix.close fd;
      Stdlib.exit 0
    | `In_the_parent child_pid ->
      let previous_signal_handler =
        Stdlib.Sys.signal Stdlib.Sys.sigalrm (Signal_handle (fun _ -> raise Exit))
      in
      Fun.protect
        ~finally:(fun () ->
          let (_ : int) = Unix.alarm 0 in
          let (_ : Stdlib.Sys.signal_behavior) =
            Stdlib.Sys.signal Stdlib.Sys.sigalrm previous_signal_handler
          in
          Unix.waitpid_exn child_pid)
        (fun () ->
          let (_ : int) = Unix.alarm 1 in
          (match input_all fifo with
           | _ -> failwith "FIFO read should have been interrupted"
           | exception Exit -> ());
          Out_channel.write_all clean_file ~data:"fresh";
          assert (String.equal (input_all clean_file) "fresh")))
;;
