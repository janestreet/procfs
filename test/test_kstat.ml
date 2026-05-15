open Core

let%expect_test "Procfs.Kstat.load_exn does not raise and returns positive values" =
  let positive n = Big_int.sign_big_int n >= 0 in
  let absent_or_positive = Option.value_map ~default:true ~f:positive in
  let sane
    { Procfs.Kstat.user; nice; sys; idle; iowait; irq; softirq; steal; guest; guest_nice }
    =
    positive user
    && positive nice
    && positive sys
    && positive idle
    && absent_or_positive iowait
    && absent_or_positive irq
    && absent_or_positive softirq
    && absent_or_positive steal
    && absent_or_positive guest
    && absent_or_positive guest_nice
  in
  let _, result = Procfs.Kstat.load_exn () |> List.unzip in
  let at_least_two_elements = List.length result >= 2 in
  if at_least_two_elements && List.for_all result ~f:sane
  then printf "load_exn is sane"
  else printf "load_exn is NOT sane";
  [%expect {| load_exn is sane |}]
;;
