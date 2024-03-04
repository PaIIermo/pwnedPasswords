import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res


def pwned_api_check(password, split_point):
    sha1password = hashlib.sha1(password.encode('utf8')).hexdigest().upper()
    first_characters, tail = sha1password[:split_point], sha1password[split_point:]
    response = request_api_data(first_characters)
    return get_leaks_count(response, tail)


def get_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main(args):
    for password in args:
        count = pwned_api_check(password, 5)
        if count:
            print(f'{password} was found {count} times. You should stop using it')
        else:
            print(f'{password} has not been found! Carry on')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
