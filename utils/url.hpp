#ifndef _URL_HPP
#define _URL_HPP

#include <string_view>
#include <iostream>
#include <string>
#include <cctype>

enum class scheme : unsigned short
{
    none = 0,       // Indicates that no scheme is present
    unknown,        // Indicates the scheme is not a well-known scheme
    ftp,            // File Transfer Protocol (FTP)
    file,           // File URI Scheme
    http,           // The Hypertext Transfer Protocol URI Scheme
    https,          // The Secure Hypertext Transfer Protocol URI Scheme
    ws,             // The WebSocket URI Scheme
    wss             // The Secure WebSocket URI Scheme
};



class URL{
public:
    static int scheme_to_default_port(scheme s) noexcept{
        switch(s)
        {
        case scheme::ftp:
            return 21;
        case scheme::http:
        case scheme::ws:
            return 80;
        case scheme::https:
        case scheme::wss:
            return 443;
        default:
            break;
        }
        return 0;
    }



    static scheme string_to_scheme(std::string_view s) noexcept{
        switch(s.size()){
        case 0: // none
            return scheme::none;

        case 2: // ws
            if( std::tolower(static_cast<unsigned char>(s[0])) == 'w' &&
                std::tolower(static_cast<unsigned char>(s[1])) == 's')
                return scheme::ws;
            break;

        case 3:
            switch(std::tolower(static_cast<unsigned char>(s[0])))
            {
            case 'w': // wss
                if( std::tolower(static_cast<unsigned char>(s[1])) == 's' &&
                    std::tolower(static_cast<unsigned char>(s[2])) == 's')
                    return scheme::wss;
                break;

            case 'f': // ftp
                if( std::tolower(static_cast<unsigned char>(s[1])) == 't' &&
                    std::tolower(static_cast<unsigned char>(s[2])) == 'p')
                    return scheme::ftp;
                break;

            default:
                break;
            }
            break;

        case 4:
            switch(std::tolower(static_cast<unsigned char>(s[0])))
            {
            case 'f': // file
                if( static_cast<unsigned char>(s[1]) == 'i' &&
                    static_cast<unsigned char>(s[2]) == 'l' &&
                    static_cast<unsigned char>(s[3]) == 'e')
                    return scheme::file;
                break;

            case 'h': // http
                if( static_cast<unsigned char>(s[1]) == 't' &&
                    static_cast<unsigned char>(s[2]) == 't' &&
                    static_cast<unsigned char>(s[3]) == 'p')
                    return scheme::http;
                break;

            default:
                break;
            }
            break;

        case 5: // https
            if( static_cast<unsigned char>(s[0]) == 'h' &&
                static_cast<unsigned char>(s[1]) == 't' &&
                static_cast<unsigned char>(s[2]) == 't' &&
                static_cast<unsigned char>(s[3]) == 'p' &&
                static_cast<unsigned char>(s[4]) == 's')
                return scheme::https;
            break;

        default:
            break;
        }
        return scheme::unknown;
    }

};

#endif