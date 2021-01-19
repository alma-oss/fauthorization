namespace Lmc.Authorization

[<AutoOpen>]
module internal Utils =

    type ErrorMessage = string

    [<RequireQualifiedAccess>]
    module List =
        let toGeneric (list: _ list): System.Collections.Generic.List<_> =
            list
            |> System.Linq.Enumerable.ToList

    [<RequireQualifiedAccess>]
    module String =
        open System
        open System.Text

        let toBytes (string: string) =
            string
            |> Encoding.UTF8.GetBytes

        let toBase64 = toBytes >> Convert.ToBase64String

        let toLower (string: string) =
            string.ToLower()

    [<RequireQualifiedAccess>]
    module Hash =
        open System
        open System.Security.Cryptography

        let sha1 (value: string) =
            value
            |> String.toBytes
            |> HashAlgorithm.Create(HashAlgorithmName.SHA1.Name).ComputeHash
            |> BitConverter.ToString
            |> Seq.filter ((<>) '-')
            |> System.String.Concat
            |> String.toLower
