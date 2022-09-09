module Main

import Text.Crypt

single : IO ()
single = gensalt "$y$" 11 >>= putStrLn

run : Nat -> PrimIO ()
run Z w = MkIORes () w
run (S n) w =
  let MkIORes () w2 := toPrim single w
   in run n w2

main : IO ()
main = fromPrim $ run 10000000
