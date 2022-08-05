package main

import (
	"fmt"

	"database/sql"
	"github.com/xuri/excelize/v2"

	_ "github.com/go-sql-driver/mysql" // "_" 引入后面的包名 而不直接使用里面的定义的函数、变量、资源等
)

var (
	Db  *sql.DB
	err error
)

func init() {
	Db, err = sql.Open("mysql", "chd_go:wN6vP9Z9#hs)_894vg0rjp@tcp(rm-m5edp40r7hg34oiu8to.mysql.rds.aliyuncs.com:3306)/insurance")
	if err != nil {
		panic(err.Error())
	}
}
func main() {
	f, err := excelize.OpenFile("/Users/harry/Downloads/pa.xlsx")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		// Close the spreadsheet.
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	// Get all the rows in the Sheet1.
	rows, err := f.GetRows("行业类型映射")
	if err != nil {
		fmt.Println(err)
		return
	}

	one, two, three, four, five, six := "", "", "", "", "", ""
	for j, row := range rows {
		if j < 2 {
			continue
		}
		for i, colCell := range row {
			switch i {
			case 0:
				one = colCell
			case 1:
				two = colCell
			case 2:
				three = colCell
			case 3:
				four = colCell
			case 4:
				five = colCell
			case 5:
				six = colCell

			}
			fmt.Print(colCell, "\t")

		}
		// 写 sql 语句
		sqlStr := "insert into industry(industry_one , industry_two, industry_three, industry_four,industry_five,des) values('" + one + "','" + two + "','" + three + "','" + four + "','" + five + "','" + six + "')"
		res, err := Db.Exec(sqlStr)
		if err != nil {
			fmt.Println("err:", err)
			fmt.Println("sql:", sqlStr)
		}
		fmt.Println("res:", res)
		fmt.Println()
	}

}
