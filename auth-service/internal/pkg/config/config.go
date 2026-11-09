package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

type DBConfig struct {
	User string `env:"DB_USER,required"`
	PasswordFile string `env:"DB_PASSWORD_FILE,required"`
	Host string `env:"DB_HOST,required"`
	Port int `env:"DB_PORT" envDefault:"5432"`
	Name string `env:"DB_NAME,required"`
	Options []string `env:"DB_OPTIONS"`
}

type Config struct {
	DB DBConfig
	JWTSecretFile string `env:"JWT_SECRET_FILE,required"`
	GRPCAddr string `env:"GRPC_ADDR" envDefault:":50051"`
	AccessTokenTTL time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"15m"`
	SessionTTL time.Duration `env:"SESSION_TTL" envDefault:"2160h"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"720h"`
}

func ParseEnv() (Config, error) {
	return env.ParseAs[Config]()
}
