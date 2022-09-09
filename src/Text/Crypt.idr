module Text.Crypt

%foreign "C:idris_gensalt,libcrypt-idris"
prim__gensalt : String -> Bits32 -> PrimIO String

export
gensalt : String -> Bits32 -> IO String
gensalt pre cnt = fromPrim $ prim__gensalt pre cnt
