package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Estrutura para status de memória
type MemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// Constantes e variáveis globais
const (
	numGoroutines      = 24
	numVariableIndices = 9
)

var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
var curve = secp256k1.S256()

// Função para detectar caracteres repetidos
func hasRepeatedCharacters(key string) bool {
	if len(key) < 7 {
		return false
	}
	repeatCount := 1
	for i := 1; i < len(key); i++ {
		if key[i] == key[i-1] && key[i] != '0' {
			repeatCount++
			if repeatCount == 4 {
				return true
			}
		} else {
			repeatCount = 1
		}
	}
	return false
}

// Funções de memória
func getAvailableMemory() uint64 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	memStatus := MemoryStatusEx{}
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	ret, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		fmt.Printf("Erro ao obter memória disponível: %v\n", err)
		return 8 * 1024 * 1024 * 1024 // fallback 8GB
	}
	return memStatus.AvailPhys
}

func getMaxKeysInMemory() int {
	availableMemory := getAvailableMemory()
	usableMemory := availableMemory * 90 / 100
	maxKeys := int(usableMemory / 100) // cada chave ~100 bytes
	return maxKeys
}

// Função para gerar índices aleatórios únicos em ordem sequencial
func generateRandomIndices() []int {
	rand.Seed(time.Now().UnixNano())
	indices := make([]int, 64)
	for i := range indices {
		indices[i] = i
	}
	rand.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})
	// Garante ordenação sequencial dos índices
	selected := indices[:numVariableIndices]
	// Ordena os índices selecionados para teste sequencial
	sortInts(selected)
	return selected
}

// Função auxiliar para ordenação
func sortInts(a []int) {
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[i] > a[j] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}

// Salva índices em arquivo
func saveIndices(indices []int) error {
	var b bytes.Buffer
	for i, idx := range indices {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(idx))
	}
	return os.WriteFile("indices.txt", b.Bytes(), 0644)
}

// Carrega índices de arquivo
func loadIndices() []int {
	data, err := os.ReadFile("indices.txt")
	if err != nil {
		return nil
	}
	parts := strings.Split(string(data), ",")
	indices := make([]int, len(parts))
	for i, part := range parts {
		idx, _ := strconv.Atoi(part)
		indices[i] = idx
	}
	// Garante ordenação dos índices carregados
	sortInts(indices)
	return indices
}

// Geração de chaves com índices aleatórios
func GenerateAndSendKeys(pattern string, keysChan chan<- []string, stopSignal chan struct{}, startIndex *big.Int, variableIndices []int) {
	key := []byte(pattern)
	totalCombinations := new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(len(variableIndices))), nil)
	current := new(big.Int).Set(startIndex)

	// Garante que o padrão tem 64 caracteres
	if len(key) != 64 {
		fmt.Println("Erro: O padrão da chave deve ter exatamente 64 caracteres")
		close(keysChan)
		return
	}

	mem := getAvailableMemory()
	batchSize := int(mem / (64 * 1024))
	if batchSize < 100000 {
		batchSize = 100000
	}
	fmt.Printf("Usando batch size: %d\n", batchSize)

	batch := []string{}
	for current.Cmp(totalCombinations) < 0 {
		select {
		case <-stopSignal:
			return
		default:
			// Gera a string hexadecimal para a combinação atual
			hexStr := fmt.Sprintf("%0*x", len(variableIndices), current)
			// Atualiza apenas as posições variáveis
			for i, idx := range variableIndices {
				if idx < len(key) && i < len(hexStr) {
					key[idx] = hexStr[i]
				}
			}
			keyStr := string(key)
			// Verifica caracteres repetidos
			if !hasRepeatedCharacters(keyStr) {
				batch = append(batch, keyStr)
				if len(batch) >= batchSize {
					keysChan <- batch
					batch = []string{}
				}
			}
			current.Add(current, big.NewInt(1))
		}
	}
	if len(batch) > 0 {
		keysChan <- batch
	}
}

// Busca nas chaves geradas
func SearchInKeys(wallets []string, keysChan <-chan []string, stopSignal chan struct{}, startTime time.Time, keysChecked *int64, lastKeyTested *atomic.Value, mu *sync.Mutex) {
	ticker := time.NewTicker(2 * time.Second)
	saveTicker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer saveTicker.Stop()

	for {
		select {
		case <-stopSignal:
			return
		case batch, ok := <-keysChan:
			if !ok {
				return
			}
			var innerWg sync.WaitGroup
			for _, keyHex := range batch {
				innerWg.Add(1)
				go func(keyHex string) {
					defer innerWg.Done()
					privKey := new(big.Int)
					if _, ok := privKey.SetString(keyHex, 16); !ok {
						return
					}
					atomic.AddInt64(keysChecked, 1)
					privKeyBytes := privKey.FillBytes(make([]byte, 32))
					pubKey := GeneratePublicKey(privKeyBytes)
					addressHash160 := Hash160(pubKey)
					addressHash160Hex := fmt.Sprintf("%x", addressHash160)

					if contains(wallets, addressHash160Hex) {
						wifKey := PrivateKeyToWIF(privKey)
						address := PublicKeyToAddress(pubKey)
						saveFoundKeyDetails(privKey, wifKey, address)
						close(stopSignal)
						return
					}
					mu.Lock()
					lastKeyTested.Store(keyHex)
					mu.Unlock()
				}(keyHex)
			}
			innerWg.Wait()
		case <-ticker.C:
			mu.Lock()
			if lastKey := lastKeyTested.Load(); lastKey != nil {
				printProgress(startTime, keysChecked, lastKey.(string))
			}
			mu.Unlock()
		case <-saveTicker.C:
			mu.Lock()
			if lastKey := lastKeyTested.Load(); lastKey != nil {
				saveLastKey(lastKey.(string))
			}
			mu.Unlock()
		}
	}
}

// Monitoramento de desempenho
func monitorPerformance(keysChecked *int64, startTime time.Time) {
	ticker := time.NewTicker(600 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		elapsed := time.Since(startTime).Seconds()
		checked := atomic.LoadInt64(keysChecked)
		fmt.Printf("\n🔴 Velocidade Real: %.0f chaves/s\n", float64(checked)/elapsed)
	}
}

// Funções auxiliares
func printProgress(startTime time.Time, keysChecked *int64, lastKeyTested string) {
	elapsed := time.Since(startTime)
	keysPerSecond := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rChaves/s: %06.0f | Última chave testada: %s", keysPerSecond, lastKeyTested)
}

func contains(wallets []string, addressHash160Hex string) bool {
	for _, wallet := range wallets {
		if wallet == addressHash160Hex {
			return true
		}
	}
	return false
}

// Salvamento de resultados
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
	fmt.Println("\n-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
	if err != nil {
		fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
	}
}

func loadLastKey() string {
	file, err := os.Open("last_key.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		fmt.Printf("Erro ao carregar a última chave: %v\n", err)
		return ""
	}
	defer file.Close()

	content := make([]byte, 64)
	n, err := file.Read(content)
	if err != nil {
		fmt.Printf("Erro ao ler a última chave do arquivo: %v\n", err)
		return ""
	}
	return string(bytes.TrimSpace(content[:n]))
}

func saveLastKey(key string) {
	file, err := os.OpenFile("last_key.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar a última chave: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(key)
	if err != nil {
		fmt.Printf("Erro ao escrever a última chave no arquivo: %v\n", err)
	}
}

// Funções criptográficas
func GeneratePublicKey(privKeyBytes []byte) []byte {
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	pubKey := privKey.PubKey()
	return pubKey.SerializeCompressed()
}

func PublicKeyToAddress(pubKey []byte) string {
	pubKeyHash := Hash160(pubKey)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	return base58EncodeWithChecksum(versionedPayload)
}

func PrivateKeyToWIF(privKey *big.Int) string {
	privKeyBytes := privKey.FillBytes(make([]byte, 32))
	payload := append([]byte{0x80}, privKeyBytes...)
	payload = append(payload, 0x01)
	return base58EncodeWithChecksum(payload)
}

func Hash160(data []byte) []byte {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:])
	return ripemd160Hasher.Sum(nil)
}

func base58EncodeWithChecksum(payload []byte) string {
	checksum := checksum(payload)
	fullPayload := append(payload, checksum...)
	return base58Encode(fullPayload)
}

func base58Encode(input []byte) string {
	var result []byte
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	for _, b := range input {
		if b != 0x00 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

func AddressToHash160(address string) []byte {
	payload := base58Decode(address)
	return payload[1 : len(payload)-4]
}

func base58Decode(input string) []byte {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, char := range []byte(input) {
		value := bytes.IndexByte(base58Alphabet, char)
		if value == -1 {
			panic("Invalid Base58 character")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(value)))
	}

	decoded := result.Bytes()
	leadingZeros := 0

	for _, char := range []byte(input) {
		if char != base58Alphabet[0] {
			break
		}
		leadingZeros++
	}

	return append(make([]byte, leadingZeros), decoded...)
}

// Função principal atualizada
func main() {
	var address, pattern string
	fmt.Print("Endereço: ")
	fmt.Scanln(&address)
	fmt.Print("Padrão da chave: ")
	fmt.Scanln(&pattern)

	lastKey := loadLastKey()
	var continueProcess bool

	// Pergunta ao usuário se deseja continuar
	if lastKey != "" {
		var resposta string
		fmt.Print("Continuar do último processo interrompido? (s/n): ")
		fmt.Scanln(&resposta)
		continueProcess = strings.ToLower(resposta) == "s"
	} else {
		continueProcess = false
	}

	var startIndex *big.Int
	var variableIndices []int

	if continueProcess {
		// Carregar índice e posições salvas
		variableIndices = loadIndices()
		if variableIndices == nil || len(variableIndices) != numVariableIndices {
			fmt.Println("Erro ao carregar índices. Gerando novos índices aleatórios.")
			variableIndices = generateRandomIndices()
			saveIndices(variableIndices)
		}

		// Extrair valor hexadecimal das posições salvas
		var hexPart string
		for _, idx := range variableIndices {
			if idx < len(lastKey) {
				hexPart += string(lastKey[idx])
			}
		}

		startIndex = new(big.Int)
		startIndex.SetString(hexPart, 16)
		fmt.Printf("Continuando com índices: %v\n", variableIndices)
	} else {
		// Apagar registros antigos
		os.Remove("last_key.txt")
		os.Remove("indices.txt")

		// Gerar novos índices e começar do zero
		variableIndices = generateRandomIndices()
		saveIndices(variableIndices)
		startIndex = big.NewInt(0)
		fmt.Printf("Novos índices aleatórios gerados: %v\n", variableIndices)
	}

	walletHash160 := fmt.Sprintf("%x", AddressToHash160(address))
	wallets := []string{walletHash160}

	startTime := time.Now()
	stopSignal := make(chan struct{})
	var wg sync.WaitGroup
	var keysChecked int64
	var mu sync.Mutex
	var lastKeyTested atomic.Value
	keysChan := make(chan []string, getMaxKeysInMemory())

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SearchInKeys(wallets, keysChan, stopSignal, startTime, &keysChecked, &lastKeyTested, &mu)
		}()
	}

	go func() {
		GenerateAndSendKeys(pattern, keysChan, stopSignal, startIndex, variableIndices)
		close(keysChan)
	}()

	go monitorPerformance(&keysChecked, startTime)
	wg.Wait()
}
