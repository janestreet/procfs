open! Core
open! Async
module Pagemap = Procfs.Pagemap

let fill_iobuf_with_hex_text hex_text =
  let bytes =
    hex_text
    |> String.split ~on:' '
    |> List.filter_map ~f:(fun s ->
      let s = String.strip s in
      if String.is_empty s then None else Some s)
  in
  List.map bytes ~f:(fun s -> Char.of_int_exn (Int.Hex.of_string ("0x" ^ s)))
  |> String.of_char_list
  |> Iobuf.of_string
;;

let with_test_pagemap ~f ~hex_text =
  let iobuf = fill_iobuf_with_hex_text hex_text in
  Expect_test_helpers_async.with_temp_dir (fun tmp ->
    let tmp_file = Filename.concat tmp "pagemap" in
    let (_ : int) =
      Core_unix.with_file tmp_file ~mode:[ O_CREAT; O_RDWR ] ~f:(fun file ->
        Core_unix.write file ~buf:(Iobuf.to_bytes iobuf))
    in
    let pagemap = Core_unix.openfile ~mode:[ Core_unix.O_RDONLY ] tmp_file in
    f pagemap)
;;

(* Uses a sample (much smaller) pagemap and checks that physical address is read
   correctly. *)
let%expect_test "converting a virtual address to a physical address" =
  let test_hex_text =
    {|
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 80 a0  00 00 00 00 00 00 00 00
  11 aa 00 00 00 00 81 a0  00 00 00 00 00 00 00 00
  10 aa 00 00 01 10 81 41  00 00 00 00 00 00 00 00 |}
  in
  let%bind () =
    with_test_pagemap ~hex_text:test_hex_text ~f:(fun reader ->
      let pagemap = Pagemap.create reader in
      List.iter [ 0L; 0x2000L; 0x4000L; 0x6000L ] ~f:(fun virt ->
        let pte = Or_error.ok_exn (Procfs.Pagemap.For_testing.get_pte pagemap ~virt) in
        let pte_record = Or_error.ok_exn (Procfs.Pagemap.get_pte_record pagemap ~virt) in
        print_s
          [%message
            ""
              ~pte:(Printf.sprintf "0x%016LX" pte : string)
              (pte_record : Pagemap.Page_table_entry.t)]);
      return ())
  in
  [%expect
    {|
    ((pte 0x0000000000000000)
     (pte_record
      ((pfn ()) (swap_type ()) (swap_offset ()) (soft_dirty false)
       (exclusive_map false) (page_type Shared_anon) (swapped false)
       (present false))))
    ((pte 0xA080000000000000)
     (pte_record
      ((pfn (0)) (swap_type ()) (swap_offset ()) (soft_dirty true)
       (exclusive_map false) (page_type File_page) (swapped false)
       (present true))))
    ((pte 0xA08100000000AA11)
     (pte_record
      ((pfn (281474976754193)) (swap_type ()) (swap_offset ()) (soft_dirty true)
       (exclusive_map false) (page_type File_page) (swapped false)
       (present true))))
    ((pte 0x418110010000AA10)
     (pte_record
      ((pfn ()) (swap_type ("\000")) (swap_offset (9345983055184))
       (soft_dirty true) (exclusive_map true) (page_type Shared_anon)
       (swapped true) (present false))))
    |}];
  return ()
;;
