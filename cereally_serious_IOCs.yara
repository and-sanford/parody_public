rule sus_DB_activity : creedofbobby
{
    meta:
        tlp = "clear"
        author = "lol"
        date = "2023-12-14"
        family = "entertainment"
        external_file = "/path/to/wpm_tracking_script.py"

    strings:
        $domain1 = "www.creedthoughts.gov.www\creedthoughts" nocase wide ascii
        reference1 = "https://screenrant.com/the-office-creed-bratton-crimes/#theft"
        $user1 = "Robert`): DROP TABLE Students;--"
        reference2 = "https://xkcd.com/327/
        $wpm = external_file.var("user_wpm")
        reference3 = "https://youtu.be/u8qgehH3kEQ?si=-dh8B_j8u43IsLSU"

    condition:
        all of (
            $domain1
            $user1
            int($wpm) > 200
        )               
    alert:
        title = "Potential Suspicious Activity Detected: Prod DB dropped"
        description = "Username: Little Bobby Tables\nEndpoint: Two hands on one keyboard\C2: www.creedthoughts.gov.www\\creedthoughts"
}
