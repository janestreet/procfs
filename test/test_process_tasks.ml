open Core

let got_tasks process =
  if Procfs.Process.task_stats process |> Map.is_empty
  then print_endline "no tasks"
  else print_endline "got tasks"
;;

let%expect_test "default, true and false of ?load_tasks" =
  Procfs.self () |> got_tasks;
  Procfs.self () ~load_tasks:true |> got_tasks;
  Procfs.self () ~load_tasks:false |> got_tasks;
  [%expect
    {|
    got tasks
    got tasks
    no tasks
    |}]
;;
