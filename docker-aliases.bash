# Entry points for Docker
alias samld='docker run -it --rm -v "${AWS_DIR:-$HOME/.aws}:/aws" \
                        -e "USER=$USER" \ -e "ADFS_DOMAIN=$ADFS_DOMAIN" \
                        -e "ADFS_URL=$ADFS_URL" quay.io/turner/samlkeygen \
                        authenticate --all-accounts --auto-update'
alias awsprofs='docker run --rm -v ~/.aws:/aws quay.io/turner/samlkeygen list-profiles'
alias awsprof='docker run --rm -v ~/.aws:/aws quay.io/turner/samlkeygen select-profile'
