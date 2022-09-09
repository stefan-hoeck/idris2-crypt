module Text.Crypt

%foreign "C:idris_gensalt,libcrypt-idris"
prim__gensalt : String -> Bits32 -> PrimIO String

%foreign "C:idris_crypt,libcrypt-idris"
prim__crypt : String -> String -> String

%foreign "C:idris_checksalt,libcrypt-idris"
prim__checksalt : String -> Int

%foreign "C:idris_checkphrase,libcrypt-idris"
prim__checkphrase : String -> Int

%foreign "C:idris_crypt_check,libcrypt-idris"
prim__cryptCheck : String -> String -> Int

export %inline
gensalt : String -> Bits32 -> IO String
gensalt pre cnt = fromPrim $ prim__gensalt pre cnt

export %inline
crypt : (salt, phrase : String) -> String
crypt = prim__crypt

export %inline
cryptcheck : (key, phrase : String) -> Bool
cryptcheck key phrase = prim__cryptCheck key phrase == 0

public export
data SaltQuality = OK | Invalid | Legacy

export
Show SaltQuality where
  show OK      = "OK"
  show Invalid = "Invalid"
  show Legacy  = "Legacy"

export
checksalt : (salt : String) -> SaltQuality
checksalt salt = case prim__checksalt salt of
  0 => OK
  2 => Legacy
  _ => Invalid

export
checkphrase : (phrase : String) -> Bool
checkphrase phrase = prim__checkphrase phrase /= 0
