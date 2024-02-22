rule ft_rar
{
        meta:
                author = "Kaden Mahsoob"
                created = "2022-03-02"
                university = "Carnegie 
                description ="Detect RAR! File Magic"
        strings:
            $Rar = {52 61 72 21 1A 07}
        condition:
            $Rar at 0
}