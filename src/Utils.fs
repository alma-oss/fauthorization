namespace Alma.Authorization

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

    [<AutoOpen>]
    module Regexp =
        open System.Text.RegularExpressions

        // http://www.fssnip.net/29/title/Regular-expression-active-pattern
        let (|Regex|_|) pattern input =
            let m = Regex.Match(input, pattern)
            if m.Success then Some (List.tail [ for g in m.Groups -> g.Value ])
            else None
